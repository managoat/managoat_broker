defmodule Managoat.Broker.Response do
  @moduledoc """
  Which request a response belongs to, what status it carried, and when it
  ended — worked out from the bytes coming back from an origin.

  This is an *observer*, not a relay. The proxy sends every upstream **body**
  byte to the sandbox the instant it arrives and then hands the same bytes
  here, so framing can never delay, reorder or accumulate a body: a
  streaming reply streams whatever this module concludes, and a framing
  failure costs telemetry rather than the response. The only bytes it ever
  holds are those of a head that has not arrived in full yet, and that is
  capped.

  Heads are the exception, and only on the absolute-form path, where the
  proxy keeps the sandbox's connection alive: `Connection` describes the
  hop it arrived on, so `Managoat.Broker.Proxy` reads that head in full,
  re-emits it with this hop's own answer and hands the *original* bytes
  here afterwards. What this module frames is therefore always what the
  origin actually said. Inside a tunnel nothing is held back at all.

  ## What relaying a head verbatim is worth

  Written down because the shorthand — "byte-perfect relay is what keeps a
  stream a stream" — is not the mechanism, and the next request to rewrite
  a response head deserves an exchange rate rather than a slogan.

  Streaming is the *body* pump's doing. The proxy writes every body byte to
  the sandbox before this module sees it, and rewriting a head does not
  touch that: the absolute-form path rewrites one and streams exactly as it
  did before. So "a head cannot be rewritten or streaming would suffer" is
  not an argument, and was never the one that mattered.

  Two things are:

    * **A parse failure cannot reach the wire.** This module already runs
      the parser on every response — it has to, to know when one ended. The
      property is not that the risky code is absent, it is that the risky
      code's verdict is *telemetry*. A head OTP's parser chokes on costs a
      log line here. Re-emit heads and the same head costs the response.
    * **Header names survive as the origin wrote them.** OTP's parser
      canonicalises them: `CONTENT-TYPE` comes back `Content-Type` and
      `x-api-key` comes back `X-Api-Key`. Order and duplicates survive;
      casing does not. Re-emitting a head therefore rewrites casing on
      every response, for every agent, for good. Legal — header names are
      case-insensitive — and occasionally not harmless.

  What the property costs is every feature that would edit a response:
  dropping a `Set-Cookie` an origin is planting on the agent, adding a
  header of the proxy's own, normalising anything at all. Inside a tunnel
  none of those are available without giving it up.

  So it is a budget rather than a law, and it has been spent once already —
  on the path where the traffic is package managers and the responses are
  short. Spend it again where something needs it and the blast radius is
  understood. In a tunnel that radius is every streamed reply and every
  clone this proxy exists to carry, which is why it is still whole there.

  Agent Vault had none of this to weigh. It ran Go's `http.Server` at both
  ends — inside the CONNECT tunnel included (`internal/mitm/connect.go`) —
  so every response was parsed into an `http.Response` and rebuilt from a
  header map, and its `flushingWriter` exists to claw back the streaming
  that rebuilding takes away by default. Matching it here is a choice to be
  argued, not a default to fall back to.

  ## Correlation

  HTTP/1.1 responses come back in request order, so a FIFO of request
  descriptors is the whole correspondence, pipelining included. The proxy
  calls `expect/2` before it writes a request upstream — never after, or a
  fast origin could answer before its descriptor was queued.

  Three things do not consume a descriptor:

  - an informational `1xx` other than `101`, which precedes the real
    response to the same request;
  - a `101`, which does consume its descriptor but ends framing: what
    follows an upgrade is frames, not HTTP, so this module stops looking;
  - a response with no descriptor to attribute it to, which means sync with
    the origin is lost and framing stops rather than guessing.

  ## Endings

  `observe/2` returns the requests that finished, in completion order, as
  `{request, status, error}`. `status` is nil when no head was ever parsed.
  `error` is nil when the response completed, and otherwise one of:

  | atom | what happened |
  |---|---|
  | `:upstream_send_failed` | the request could not be written to the origin |
  | `:upstream_read_failed` | reading the response failed at the transport |
  | `:malformed_response` | the origin's head did not parse, or never ended |
  | `:upstream_closed` | the origin closed before its framed body was done |
  | `:client_closed` | the sandbox went away before the relay finished |
  | `:request_too_large` | the request body passed the configured cap |
  | `:response_too_large` | the response body passed the configured cap |

  A response whose head parsed and whose body then failed carries both its
  status and its error.
  """

  alias Managoat.Broker.HTTP

  # A head this long has not arrived in full and is not going to be a head.
  # Bounded because the bytes of an incomplete head are the one thing this
  # module holds on to.
  @max_head 64 * 1024

  @typedoc "Whatever the proxy needs to attribute a finished response."
  @type request :: term()

  @type reason ::
          :upstream_send_failed
          | :upstream_read_failed
          | :malformed_response
          | :upstream_closed
          | :client_closed
          | :request_too_large
          | :response_too_large

  @typedoc "A finished request: what it was, the status it got, why it failed."
  @type finished :: {request(), 100..599 | nil, reason() | nil}

  @type t :: %__MODULE__{
          pending: [request()],
          current: {request(), 100..599, HTTP.framing()} | nil,
          buffer: binary(),
          mode: :framing | :done | :halt,
          limit: pos_integer() | :infinity,
          body: non_neg_integer()
        }

  # `pending` is a plain list appended to at the end. It holds the requests
  # written upstream and not yet answered, which is one deep unless a
  # client pipelines, so the append is cheaper than the machinery a queue
  # would bring — and a queue's type is opaque, which would make this
  # struct opaque to the proxy that has to carry it.
  defstruct pending: [],
            current: nil,
            buffer: "",
            mode: :framing,
            limit: :infinity,
            body: 0

  @doc """
  A framer with nothing outstanding, capping each response body at `limit`
  bytes (`:infinity`, the default, for no cap).

  A cap here can only end a response, never prevent one: the proxy writes
  every byte to the sandbox before this module sees it, which is what
  keeps a stream a stream. So an over-long response reaches the sandbox up
  to roughly the limit and the connection is then torn down, rather than
  being answered with a status. Agent Vault's response cap ends the same
  way — it aborts the connection mid-stream — and defaults to unlimited,
  which is why this does too.
  """
  @spec new(pos_integer() | :infinity) :: t()
  def new(limit \\ :infinity), do: %__MODULE__{limit: limit}

  @doc """
  Has framing stopped because a response passed its cap? The relay closes
  the connection when it has; nothing else ends a response early.
  """
  @spec halted?(t()) :: boolean()
  def halted?(%__MODULE__{mode: :halt}), do: true
  def halted?(%__MODULE__{}), do: false

  @doc """
  Note a request written upstream. Call this *before* the write: an origin
  may answer faster than the next line of code runs.
  """
  @spec expect(t(), request()) :: t()
  def expect(%__MODULE__{} = state, request) do
    %{state | pending: state.pending ++ [request]}
  end

  @doc "Is anything still outstanding?"
  @spec idle?(t()) :: boolean()
  def idle?(%__MODULE__{current: nil, pending: pending}), do: pending == []
  def idle?(%__MODULE__{}), do: false

  @doc """
  Feed the bytes that just came back. Returns the new state and the
  requests that finished on these bytes, in completion order.
  """
  @spec observe(t(), binary()) :: {t(), [finished()]}
  def observe(state, data), do: step(state, data, [])

  @doc """
  The upstream closed. A body delimited by the close ends here and ends
  well; anything else outstanding was cut short.
  """
  @spec closed(t()) :: {t(), [finished()]}
  def closed(%__MODULE__{current: {request, status, :until_close}} = state) do
    drain(%{state | current: nil}, [{request, status, nil}], :upstream_closed)
  end

  def closed(%__MODULE__{} = state), do: drain(state, [], :upstream_closed)

  @doc "Everything still outstanding failed, for one reason."
  @spec failed(t(), reason()) :: {t(), [finished()]}
  def failed(%__MODULE__{} = state, reason), do: drain(state, [], reason)

  # ---------------------------------------------------------------------------

  defp drain(state, finished, reason) do
    finished =
      case state.current do
        nil -> finished
        {request, status, _framing} -> finished ++ [{request, status, reason}]
      end

    rest = Enum.map(state.pending, &{&1, nil, reason})

    {%{state | current: nil, pending: [], buffer: "", mode: :done}, finished ++ rest}
  end

  # Framing has stopped: an upgrade, or a response nothing asked for. The
  # bytes still reach the sandbox; this module has nothing left to say.
  defp step(%__MODULE__{mode: mode} = state, _data, finished) when mode in [:done, :halt],
    do: {state, finished}

  defp step(%__MODULE__{current: {_, _, _}} = state, data, finished) do
    {request, status, framing} = state.current

    case HTTP.take_body(framing, data) do
      {:done, consumed, rest} ->
        if over_limit?(state, consumed) do
          {%{state | current: nil, mode: :halt},
           finished ++ [{request, status, :response_too_large}]}
        else
          step(%{state | current: nil, body: 0}, rest, finished ++ [{request, status, nil}])
        end

      {:partial, consumed, framing} ->
        if over_limit?(state, consumed) do
          {%{state | current: nil, mode: :halt},
           finished ++ [{request, status, :response_too_large}]}
        else
          {%{state | current: {request, status, framing}, body: state.body + byte_size(consumed)},
           finished}
        end
    end
  end

  defp step(%__MODULE__{} = state, data, finished) do
    buffer = state.buffer <> data

    case HTTP.parse_response(buffer) do
      {:ok, head, rest} ->
        head(%{state | buffer: ""}, head, rest, finished)

      {:more, _} when byte_size(buffer) > @max_head ->
        drain(%{state | buffer: ""}, finished, :malformed_response)

      {:more, _} ->
        {%{state | buffer: buffer}, finished}

      {:error, _reason} ->
        drain(%{state | buffer: ""}, finished, :malformed_response)
    end
  end

  defp over_limit?(%__MODULE__{limit: :infinity}, _consumed), do: false

  defp over_limit?(%__MODULE__{limit: limit, body: body}, consumed),
    do: body + byte_size(consumed) > limit

  # `100 Continue` and its kin precede the real response to the same
  # request, so the descriptor stays where it is.
  defp head(state, %{status: status}, rest, finished) when status in 100..199 and status != 101 do
    step(state, rest, finished)
  end

  defp head(state, head, rest, finished) do
    case state.pending do
      [request | pending] ->
        state = %{state | pending: pending}

        if head.status == 101 do
          # The upgrade succeeded: what follows is frames. The request is
          # over as far as HTTP is concerned, and framing stops.
          {%{state | mode: :done}, finished ++ [{request, head.status, nil}]}
        else
          framing = HTTP.response_framing(head.status, head.headers, method(request))
          step(%{state | current: {request, head.status, framing}, body: 0}, rest, finished)
        end

      [] ->
        # A response to a request that was never made. Sync with the origin
        # is gone and guessing would misattribute the next one.
        {%{state | mode: :done}, finished}
    end
  end

  # A descriptor is opaque but for this: `HEAD` never has a response body,
  # however the response frames itself.
  defp method(%{method: method}) when is_binary(method), do: method
  defp method(_), do: ""
end
