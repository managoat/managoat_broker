defmodule Managoat.Broker.ReflectionGuard do
  @moduledoc false
  # A protected request carries a bearer the sandbox never holds. If the
  # origin, a CDN error page or a debug echo writes it back, the response
  # would hand it over. Only the proxy knows the value, so only the proxy
  # can look for it. `Managoat.Broker.ProtectedRule` is the contract; this
  # is the scanner the response gate (`Managoat.Broker.HTTPOnly`) drives.
  #
  # It answers "refuse" and never "rewrite": a response that holds the
  # bearer is cut, not scrubbed. Rewriting a framed stream means re-framing
  # it (a `Content-Length` no longer true, chunk sizes to recompute), and a
  # scrubber that misses one form still ships the rest of a response the
  # origin should never have produced.
  #
  # The body is scanned incrementally and is never accumulated. Two things
  # make that sound rather than merely fast:
  #
  #   * What is scanned is the *decoded* body. A chunked response can put
  #     `\r\n1f\r\n` in the middle of the value, so the chunk framing is
  #     stepped over (and forwarded verbatim) instead of being searched.
  #   * Bytes are released only when they cannot be the start of the value.
  #     Forward-then-scan with a tail buffer would catch a value split
  #     across two reads, but only after its first half had reached the
  #     sandbox. So the longest suffix of what is in hand that is a proper
  #     prefix of the value is held until the next read settles it. For
  #     ordinary traffic that suffix is empty and nothing waits; at most
  #     `byte_size(value) - 1` bytes ever do.
  #
  # The struct holds the value, so its inspection is empty.

  @derive {Inspect, only: []}
  defstruct needles: [], pattern: nil, mode: :raw, held: [], held_data: ""

  @type segment :: {:data | :frame, binary()}
  @type t :: %__MODULE__{
          needles: [binary()],
          pattern: :binary.cp() | nil,
          mode: :raw | {:size, binary()} | {:data, non_neg_integer()} | {:crlf, 1..2} | :trailers,
          held: [segment()],
          held_data: binary()
        }

  @doc """
  The byte strings a reflection of `bearer` is recognised by: the value
  itself, which every longer string holding it (`Bearer <value>`) contains,
  and its JSON spelling where that differs (`/` written `\\/`).
  """
  @spec needles(binary()) :: [binary()]
  def needles(bearer) when is_binary(bearer) and bearer != "" do
    Enum.uniq([bearer, String.replace(bearer, "/", "\\/")])
  end

  @spec new([binary()] | nil) :: t() | nil
  def new(nil), do: nil
  def new(needles), do: %__MODULE__{needles: needles, pattern: :binary.compile_pattern(needles)}

  @doc "Does a raw response head hold the value, in any header or the status line?"
  @spec reflects?(t(), binary()) :: boolean()
  def reflects?(%__MODULE__{pattern: pattern}, raw), do: :binary.match(raw, pattern) != :nomatch

  @doc """
  Is the body in a coding this scanner cannot read? The protected request
  asked for `identity`, so any other `Content-Encoding` is an origin
  ignoring that, and an unread body is not a scanned one.
  """
  @spec encoded?([{binary(), binary()}]) :: boolean()
  def encoded?(headers) do
    Enum.any?(headers, fn {name, value} ->
      String.downcase(name) == "content-encoding" and
        value
        |> String.downcase()
        |> String.split(",")
        |> Enum.any?(&(String.trim(&1) not in ["", "identity"]))
    end)
  end

  @doc "Begin a body delimited by `framing`."
  @spec body(t(), term()) :: t()
  def body(%__MODULE__{} = guard, :chunked), do: %{guard | mode: {:size, ""}}
  def body(%__MODULE__{} = guard, _framing), do: %{guard | mode: :raw}

  @doc """
  The next raw body bytes. Returns what may be forwarded now, which is
  everything but a trailing candidate for the start of the value.
  """
  @spec scan(t() | nil, binary()) ::
          {:ok, t() | nil, iodata()} | {:error, :credential_reflected | :malformed_response}
  def scan(nil, raw), do: {:ok, nil, raw}

  def scan(%__MODULE__{} = guard, raw) do
    with {:ok, segments, mode} <- segments(guard.mode, raw, []) do
      data = IO.iodata_to_binary([guard.held_data | for({:data, bytes} <- segments, do: bytes)])

      if :binary.match(data, guard.pattern) == :nomatch do
        keep = guard.needles |> Enum.map(&candidate(data, &1)) |> Enum.max()
        {out, held} = release(guard.held ++ segments, byte_size(data) - keep, [])
        held_data = binary_part(data, byte_size(data) - keep, keep)
        {:ok, %{guard | mode: mode, held: held, held_data: held_data}, out}
      else
        {:error, :credential_reflected}
      end
    end
  end

  @doc "The body ended, so what was held is not the value after all."
  @spec flush(t() | nil) :: iodata()
  def flush(nil), do: []
  def flush(%__MODULE__{held: held}), do: Enum.map(held, &elem(&1, 1))

  # The longest suffix of `data` that is a proper prefix of `needle`.
  # Candidates are the places the needle's first byte occurs in the last
  # `byte_size(needle) - 1` bytes, earliest (longest) first.
  defp candidate(data, needle) do
    size = byte_size(data)
    window = min(size, byte_size(needle) - 1)

    data
    |> :binary.matches(binary_part(needle, 0, 1), scope: {size - window, window})
    |> Enum.find_value(0, fn {at, _} ->
      length = size - at
      if binary_part(data, at, length) == binary_part(needle, 0, length), do: length
    end)
  end

  # Everything before the `offset`th data byte goes out, framing included;
  # everything from it on waits, so the wire order never changes.
  defp release([], _offset, out), do: {Enum.reverse(out), []}
  defp release([{:frame, bytes} | rest], offset, out), do: release(rest, offset, [bytes | out])

  defp release([{:data, bytes} | rest], offset, out) when byte_size(bytes) <= offset,
    do: release(rest, offset - byte_size(bytes), [bytes | out])

  defp release([{:data, bytes} | rest], offset, out) do
    <<ready::binary-size(^offset), held::binary>> = bytes
    {Enum.reverse([ready | out]), [{:data, held} | rest]}
  end

  # Raw bytes into what is body and what is chunk framing. Trailers are
  # headers, so they are searched like data. A chunk extension is refused:
  # it is the one part of the framing an origin can put text in, nothing
  # sends them, and refusing is cheaper than searching framing too.
  defp segments(mode, "", acc), do: {:ok, Enum.reverse(acc), mode}
  defp segments(:raw, raw, acc), do: {:ok, Enum.reverse([{:data, raw} | acc]), :raw}
  defp segments(:trailers, raw, acc), do: {:ok, Enum.reverse([{:data, raw} | acc]), :trailers}

  defp segments({:size, line}, raw, acc) do
    {part, rest} =
      case :binary.match(raw, "\n") do
        {at, 1} ->
          {binary_part(raw, 0, at + 1), binary_part(raw, at + 1, byte_size(raw) - at - 1)}

        :nomatch ->
          {raw, nil}
      end

    cond do
      not Regex.match?(~r/\A[0-9A-Fa-f \t\r\n]*\z/, part) ->
        {:error, :malformed_response}

      is_nil(rest) ->
        {:ok, Enum.reverse([{:frame, part} | acc]), {:size, line <> part}}

      true ->
        mode =
          case (line <> part) |> String.trim() |> String.to_integer(16) do
            0 -> :trailers
            size -> {:data, size}
          end

        segments(mode, rest, [{:frame, part} | acc])
    end
  end

  defp segments({:data, left}, raw, acc) when byte_size(raw) < left,
    do: {:ok, Enum.reverse([{:data, raw} | acc]), {:data, left - byte_size(raw)}}

  defp segments({:data, left}, raw, acc) do
    <<data::binary-size(^left), rest::binary>> = raw
    segments({:crlf, 2}, rest, [{:data, data} | acc])
  end

  defp segments({:crlf, left}, raw, acc) when byte_size(raw) < left,
    do: {:ok, Enum.reverse([{:frame, raw} | acc]), {:crlf, left - byte_size(raw)}}

  defp segments({:crlf, left}, raw, acc) do
    <<frame::binary-size(^left), rest::binary>> = raw
    segments({:size, ""}, rest, [{:frame, frame} | acc])
  end
end
