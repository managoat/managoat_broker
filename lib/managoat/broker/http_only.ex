defmodule Managoat.Broker.HTTPOnly do
  @moduledoc false
  # Opted-in sessions need a gate in front of the response relay, not just
  # an observer after it. Hold bounded heads; stream framed bodies. A bad
  # packet is discarded in full, even if it began with otherwise safe bytes.
  alias Managoat.Broker.HTTP

  @max_head 64 * 1024
  @header_name ~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/
  @header_controls ~r/[\x00-\x08\x0A-\x1F\x7F]/
  defstruct pending: [], body: nil, buffer: ""

  @type t :: %__MODULE__{pending: [binary()], body: term(), buffer: binary()}
  @type reason :: :upstream_upgrade | :malformed_response

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

  @spec expect(t() | nil, binary()) :: t() | nil
  def expect(nil, _method), do: nil
  def expect(state, method), do: %{state | pending: state.pending ++ [method]}

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
        step(%{state | body: nil}, rest, [consumed | bytes])

      {:partial, consumed, framing} ->
        if bounded_chunk_line?(framing),
          do: {:ok, %{state | body: framing}, [consumed | bytes]},
          else: {:error, :malformed_response}
    end
  end

  defp step(state, data, bytes) do
    buffer = state.buffer <> data

    case HTTP.parse_response(buffer) do
      {:ok, head, rest} ->
        length = byte_size(buffer) - byte_size(rest)

        if length <= @max_head do
          accept_head(%{state | buffer: ""}, head, rest, [binary_part(buffer, 0, length) | bytes])
        else
          {:error, :malformed_response}
        end

      {:more, _} when byte_size(buffer) <= @max_head ->
        {:ok, %{state | buffer: buffer}, bytes}

      _ ->
        {:error, :malformed_response}
    end
  end

  defp accept_head(_state, %{status: 101}, _rest, _bytes), do: {:error, :upstream_upgrade}
  defp accept_head(%{pending: []}, _head, _rest, _bytes), do: {:error, :malformed_response}

  defp accept_head(state, %{status: status}, rest, bytes) when status in 100..199,
    do: step(state, rest, bytes)

  defp accept_head(%{pending: [method | pending]} = state, head, rest, bytes) do
    if unambiguous_framing?(head.headers) do
      framing = HTTP.response_framing(head.status, head.headers, method)
      step(%{state | pending: pending, body: framing}, rest, bytes)
    else
      {:error, :malformed_response}
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
