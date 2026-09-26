defmodule Managoat.Broker.HTTPOnly do
  @moduledoc false
  # Opted-in sessions need a gate in front of the response relay, not just
  # an observer after it. Hold bounded heads; stream framed bodies. A bad
  # packet is discarded in full, even if it began with otherwise safe bytes.
  #
  # A protected request also queues a `ReflectionGuard` holding the bearer
  # it was sent with. Its response head is searched before it is released,
  # a body in a coding the guard cannot read is refused, and the body is
  # searched as it streams. Responses to other requests carry no guard and
  # take the path they always did.
  alias Managoat.Broker.{HTTP, ReflectionGuard}

  @max_head 64 * 1024
  @header_name ~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/
  @header_controls ~r/[\x00-\x08\x0A-\x1F\x7F]/
  defstruct pending: [], body: nil, buffer: "", guard: nil

  @type t :: %__MODULE__{
          pending: [{binary(), ReflectionGuard.t() | nil}],
          body: term(),
          buffer: binary(),
          guard: ReflectionGuard.t() | nil
        }
  @type reason ::
          :upstream_upgrade
          | :malformed_response
          | :credential_reflected
          | :protected_response_encoded

  @spec new(boolean()) :: t() | nil
  def new(false), do: nil
  def new(true), do: %__MODULE__{}

  @spec check_request(boolean(), binary(), [{binary(), binary()}]) ::
          :ok | {:error, :protocol_upgrade | :unsafe_request}
  def check_request(false, _method, _headers), do: :ok

  def check_request(true, method, headers) do
    cond do
      Enum.any?(headers, &unsafe_header?/1) -> {:error, :unsafe_request}
      not unambiguous_framing?(headers) -> {:error, :unsafe_request}
      method == "CONNECT" or Enum.any?(headers, &upgrade_header?/1) -> {:error, :protocol_upgrade}
      true -> :ok
    end
  end

  @spec check_framing(boolean(), [{binary(), binary()}], [{binary(), binary()}]) ::
          :ok | {:error, :unsafe_request}
  def check_framing(false, _original, _outgoing), do: :ok

  def check_framing(true, original, outgoing) do
    if HTTP.body_framing(%{headers: original}) == HTTP.body_framing(%{headers: outgoing}),
      do: :ok,
      else: {:error, :unsafe_request}
  end

  # Custom header names/values are serialized after this check. A CRLF in
  # an unrelated value could otherwise manufacture an Upgrade header on the
  # wire that did not exist in the list we inspected.
  defp unsafe_header?({name, value}),
    do: not Regex.match?(@header_name, name) or Regex.match?(@header_controls, value)

  defp upgrade_header?({name, value}) do
    case String.downcase(name) do
      "upgrade" ->
        true

      name when name in ["connection", "proxy-connection"] ->
        value
        |> String.downcase()
        |> String.split(",")
        |> Enum.any?(&(String.trim(&1) == "upgrade"))

      _ ->
        false
    end
  end

  @spec expect(t() | nil, binary(), ReflectionGuard.t() | nil) :: t() | nil
  def expect(state, method, guard \\ nil)
  def expect(nil, _method, _guard), do: nil
  def expect(state, method, guard), do: %{state | pending: state.pending ++ [{method, guard}]}

  @doc """
  Is the gate between responses: nothing expected, nothing held? A reply the
  proxy writes itself may only go out then.
  """
  @spec idle?(t() | nil) :: boolean()
  def idle?(nil), do: true
  def idle?(%__MODULE__{pending: [], body: nil, buffer: ""}), do: true
  def idle?(%__MODULE__{}), do: false

  @doc """
  The origin closed. Bytes a guard was still holding were the start of
  nothing, and belong to a body that only the close ends.
  """
  @spec closed(t() | nil) :: binary()
  def closed(%__MODULE__{guard: guard}),
    do: guard |> ReflectionGuard.flush() |> IO.iodata_to_binary()

  def closed(nil), do: ""

  @spec filter(t() | nil, binary()) :: {:ok, t() | nil, binary()} | {:error, reason()}
  def filter(nil, data), do: {:ok, nil, data}

  def filter(state, data) do
    case step(state, data, []) do
      {:ok, state, bytes} -> {:ok, state, bytes |> Enum.reverse() |> IO.iodata_to_binary()}
      {:error, _} = error -> error
    end
  rescue
    _ -> {:error, :malformed_response}
  end

  defp step(state, "", bytes), do: {:ok, state, bytes}

  defp step(%{body: body} = state, data, bytes) when not is_nil(body) do
    case HTTP.take_body(body, data) do
      {:done, consumed, rest} ->
        with {:ok, guard, safe} <- ReflectionGuard.scan(state.guard, consumed) do
          step(%{state | body: nil, guard: nil}, rest, [
            [safe | ReflectionGuard.flush(guard)] | bytes
          ])
        end

      {:partial, consumed, framing} ->
        with true <- bounded_chunk_line?(framing),
             {:ok, guard, safe} <- ReflectionGuard.scan(state.guard, consumed) do
          {:ok, %{state | body: framing, guard: guard}, [safe | bytes]}
        else
          false -> {:error, :malformed_response}
          {:error, _} = error -> error
        end
    end
  end

  defp step(state, data, bytes) do
    buffer = state.buffer <> data

    case HTTP.parse_response(buffer) do
      {:ok, head, rest} ->
        length = byte_size(buffer) - byte_size(rest)

        if length <= @max_head do
          accept_head(%{state | buffer: ""}, head, binary_part(buffer, 0, length), rest, bytes)
        else
          {:error, :malformed_response}
        end

      {:more, _} when byte_size(buffer) <= @max_head ->
        {:ok, %{state | buffer: buffer}, bytes}

      _ ->
        {:error, :malformed_response}
    end
  end

  defp accept_head(_state, %{status: 101}, _raw, _rest, _bytes), do: {:error, :upstream_upgrade}
  defp accept_head(%{pending: []}, _head, _raw, _rest, _bytes), do: {:error, :malformed_response}

  defp accept_head(%{pending: [{method, guard} | pending]} = state, head, raw, rest, bytes) do
    cond do
      # Informational heads included: they answer the same request.
      guard != nil and ReflectionGuard.reflects?(guard, raw) ->
        {:error, :credential_reflected}

      head.status in 100..199 ->
        step(state, rest, [raw | bytes])

      not unambiguous_framing?(head.headers) ->
        {:error, :malformed_response}

      guard != nil and ReflectionGuard.encoded?(head.headers) ->
        {:error, :protected_response_encoded}

      true ->
        framing = HTTP.response_framing(head.status, head.headers, method)
        guard = guard && ReflectionGuard.body(guard, framing)
        step(%{state | pending: pending, body: framing, guard: guard}, rest, [raw | bytes])
    end
  end

  # Reject ambiguous lengths instead of guessing where the next head starts.
  # The strict mode accepts the only transfer coding this HTTP slice frames.
  defp unambiguous_framing?(headers) do
    lengths = values(headers, "content-length")
    encodings = values(headers, "transfer-encoding")

    case {lengths, encodings} do
      {[], []} -> true
      {[], [encoding]} -> String.downcase(String.trim(encoding)) == "chunked"
      {[length], []} -> Regex.match?(~r/\A[0-9]+\z/, String.trim(length))
      _ -> false
    end
  end

  defp values(headers, name),
    do: for({key, value} <- headers, String.downcase(key) == name, do: value)

  defp bounded_chunk_line?({:chunked, {kind, line}}) when kind in [:size, :trailers],
    do: byte_size(line) <= @max_head

  defp bounded_chunk_line?(_framing), do: true
end
