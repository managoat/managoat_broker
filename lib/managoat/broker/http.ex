defmodule Managoat.Broker.HTTP do
  @moduledoc """
  The slice of HTTP/1.1 the proxy has to understand: a head in either
  direction, and how long the body after it is.

  Bodies are never interpreted or accumulated. Framing says where one ends
  so the next head can be found and a request can be told it is over; every
  byte is relayed as it arrives, which is what keeps a streaming model
  reply a stream.
  """

  @type head :: %{
          method: String.t(),
          target: String.t(),
          version: {integer(), integer()},
          headers: [{String.t(), String.t()}]
        }

  @type response_head :: %{
          status: 100..599,
          reason: String.t(),
          version: {integer(), integer()},
          headers: [{String.t(), String.t()}]
        }

  @typedoc """
  How the body after a head is delimited. `:until_close` is a response
  with neither a length nor chunked framing: the body is everything up to
  the close, which is therefore the only end-of-message signal.
  """
  @type framing :: :none | {:length, non_neg_integer()} | :chunked | :until_close

  @doc """
  Parse a request head off the front of `buffer`. `{:more, buffer}` when the
  head is not complete yet, `{:ok, head, rest}` with the bytes after the
  blank line, `{:error, reason}` on garbage.
  """
  @spec parse_request(binary()) :: {:ok, head(), binary()} | {:more, binary()} | {:error, term()}
  def parse_request(buffer) do
    case :erlang.decode_packet(:http_bin, buffer, []) do
      {:ok, {:http_request, method, target, version}, rest} ->
        parse_headers(rest, %{
          method: method_string(method),
          target: target_string(target),
          version: version,
          headers: []
        })

      {:ok, {:http_error, line}, _} ->
        {:error, {:bad_request_line, line}}

      {:ok, other, _} ->
        {:error, {:unexpected, other}}

      {:more, _} ->
        {:more, buffer}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_headers(buffer, head) do
    case :erlang.decode_packet(:httph_bin, buffer, []) do
      {:ok, {:http_header, _, name, _, value}, rest} ->
        parse_headers(rest, %{head | headers: [{header_string(name), value} | head.headers]})

      {:ok, :http_eoh, rest} ->
        {:ok, %{head | headers: Enum.reverse(head.headers)}, rest}

      {:ok, {:http_error, line}, _} ->
        {:error, {:bad_header, line}}

      {:more, _} ->
        # The whole head has to be re-parsed from the request line; the
        # caller keeps the original buffer and calls again with more bytes.
        :more

      {:error, reason} ->
        {:error, reason}
    end
    |> case do
      :more -> {:more, :incomplete}
      other -> other
    end
  end

  @doc """
  Parse a response head off the front of `buffer`. `{:more, buffer}` when
  the head is not complete yet, `{:ok, head, rest}` with the bytes after
  the blank line, `{:error, reason}` on garbage. The mirror of
  `parse_request/1`.
  """
  @spec parse_response(binary()) ::
          {:ok, response_head(), binary()} | {:more, binary()} | {:error, term()}
  def parse_response(buffer) do
    case :erlang.decode_packet(:http_bin, buffer, []) do
      {:ok, {:http_response, version, status, reason}, rest} ->
        parse_headers(rest, %{
          status: status,
          reason: to_string(reason),
          version: version,
          headers: []
        })

      {:ok, {:http_error, line}, _} ->
        {:error, {:bad_status_line, line}}

      {:ok, other, _} ->
        {:error, {:unexpected, other}}

      {:more, _} ->
        {:more, buffer}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  How the body after a response with `status` and `headers` is delimited,
  for a request that used `method` (RFC 9112 §6.3).

  The status and the method decide before the headers do: a `HEAD` never
  has a body however it is framed, and neither does `1xx`, `204` or `304`.
  A response that is framed by neither `Transfer-Encoding: chunked` nor
  `Content-Length` runs to the close of the connection, which is then the
  only signal that it ended.
  """
  @spec response_framing(100..599, [{String.t(), String.t()}], String.t()) :: framing()
  def response_framing(status, headers, method)

  def response_framing(_status, _headers, "HEAD"), do: :none
  def response_framing(status, _headers, _method) when status in 100..199, do: :none
  def response_framing(204, _headers, _method), do: :none
  def response_framing(304, _headers, _method), do: :none

  def response_framing(_status, headers, _method) do
    case body_framing(%{headers: headers}) do
      :none -> :until_close
      framing -> framing
    end
  end

  @doc "How the request body after `head` is delimited (RFC 9112 §6)."
  @spec body_framing(head() | %{headers: [{String.t(), String.t()}]}) :: framing()
  def body_framing(%{headers: headers}) do
    te = header(headers, "transfer-encoding")
    cl = header(headers, "content-length")

    cond do
      is_binary(te) and String.contains?(String.downcase(te), "chunked") -> :chunked
      is_binary(cl) -> {:length, cl |> String.trim() |> String.to_integer()}
      true -> :none
    end
  end

  @doc "The first value of header `name` (case-insensitive), or nil."
  @spec header([{String.t(), String.t()}], String.t()) :: String.t() | nil
  def header(headers, name) do
    down = String.downcase(name)

    Enum.find_value(headers, fn {k, v} ->
      if String.downcase(k) == down, do: v
    end)
  end

  @doc "Serialise a head back to bytes, with `target` as the request-target."
  @spec encode_request(head(), String.t()) :: iodata()
  def encode_request(%{method: method, version: {maj, min}, headers: headers}, target) do
    [
      method,
      " ",
      target,
      " HTTP/#{maj}.#{min}\r\n",
      Enum.map(headers, fn {k, v} -> [k, ": ", v, "\r\n"] end),
      "\r\n"
    ]
  end

  @doc """
  The host and port a request-target names, and the origin-form target to
  forward. Absolute-form (`http://host/path`) is what a client sends a
  forward proxy for plain HTTP; an authority (`host:port`) is a `CONNECT`.

  An IPv6 literal is bracketed in both forms — `CONNECT [::1]:8443` and
  `GET http://[::1]:8080/x` — since without brackets there is no telling
  which colon separates the port. The host is returned unbracketed, which
  is what a rule matches and what a certificate has to cover.
  """
  @spec destination(head()) ::
          {:ok, {String.t(), :inet.port_number()}, String.t()} | {:error, :bad_target}
  def destination(%{method: "CONNECT", target: target}) do
    with {:ok, host, port} <- split_authority(target),
         {p, ""} when p in 1..65_535 <- Integer.parse(port) do
      {:ok, {host, p}, target}
    else
      _ -> {:error, :bad_target}
    end
  end

  def destination(%{target: "http://" <> _ = target}) do
    case URI.parse(target) do
      %URI{host: host, port: port} = uri when is_binary(host) ->
        path = if uri.path in [nil, ""], do: "/", else: uri.path
        query = if uri.query, do: "?" <> uri.query, else: ""
        {:ok, {host, port || 80}, path <> query}

      _ ->
        {:error, :bad_target}
    end
  end

  def destination(_), do: {:error, :bad_target}

  # `host:port`, or `[v6]:port` — an IPv6 literal is bracketed precisely
  # because it is full of colons, so the brackets are what say which colon
  # is the port separator. The host comes back without them: it is what
  # rules match, what SNI would name and what a certificate has to cover,
  # and none of those want the brackets. The target is forwarded as sent.
  defp split_authority("[" <> rest) do
    case String.split(rest, "]:", parts: 2) do
      [host, port] -> {:ok, host, port}
      _ -> :error
    end
  end

  defp split_authority(target) do
    case String.split(target, ":") do
      [host, port] -> {:ok, host, port}
      _ -> :error
    end
  end

  @doc """
  Split `buffer` per `framing`: `{:done, consumed, rest}` once the whole
  body is in hand, `{:partial, consumed, state}` when more is needed and
  `consumed` (the whole buffer) may be forwarded. Chunked bodies are
  forwarded verbatim, framing included; the state remembers where in the
  chunk stream the buffer ended. `:until_close` is always `{:partial, ...}`
  — only the close ends it, and the caller turns that into the end.
  """
  @spec take_body(framing() | {:chunked, term()}, binary()) ::
          {:done, binary(), binary()} | {:partial, binary(), framing() | {:chunked, term()}}
  def take_body(:none, buffer), do: {:done, "", buffer}

  # Nothing but the close ends this body, so every byte in hand is body and
  # more is always wanted. The caller turns the close into `{:done, ...}`.
  def take_body(:until_close, buffer), do: {:partial, buffer, :until_close}

  def take_body({:length, n}, buffer) when byte_size(buffer) >= n do
    <<body::binary-size(n), rest::binary>> = buffer
    {:done, body, rest}
  end

  def take_body({:length, n}, buffer), do: {:partial, buffer, {:length, n - byte_size(buffer)}}

  def take_body(:chunked, buffer), do: take_body({:chunked, {:size, ""}}, buffer)

  def take_body({:chunked, state}, buffer) do
    case chunks(buffer, state) do
      {:done, rest} ->
        {:done, binary_part(buffer, 0, byte_size(buffer) - byte_size(rest)), rest}

      {:partial, state} ->
        {:partial, buffer, {:chunked, state}}
    end
  end

  # The chunk stream: `{:size, acc}` reading a size line, `{:data, n}` inside
  # a chunk with n bytes left (its trailing CRLF included), `{:trailers, acc}`
  # after the zero chunk until the blank line.
  defp chunks(buffer, {:size, acc}) do
    case take_line(buffer) do
      {line, rest} ->
        case chunk_size(acc <> line) do
          0 -> chunks(rest, {:trailers, ""})
          size -> chunks(rest, {:data, size + 2})
        end

      :nomatch ->
        {:partial, {:size, acc <> buffer}}
    end
  end

  defp chunks(buffer, {:data, n}) when byte_size(buffer) >= n do
    chunks(binary_part(buffer, n, byte_size(buffer) - n), {:size, ""})
  end

  defp chunks(buffer, {:data, n}), do: {:partial, {:data, n - byte_size(buffer)}}

  defp chunks(buffer, {:trailers, acc}) do
    case take_line(buffer) do
      {line, rest} ->
        if String.trim(acc <> line) == "", do: {:done, rest}, else: chunks(rest, {:trailers, ""})

      :nomatch ->
        {:partial, {:trailers, acc <> buffer}}
    end
  end

  defp take_line(buffer) do
    case :binary.match(buffer, "\n") do
      {pos, 1} ->
        {binary_part(buffer, 0, pos + 1),
         binary_part(buffer, pos + 1, byte_size(buffer) - pos - 1)}

      :nomatch ->
        :nomatch
    end
  end

  defp chunk_size(line) do
    line
    |> String.trim()
    |> String.split(";", parts: 2)
    |> hd()
    |> String.trim()
    |> String.to_integer(16)
  end

  defp method_string(m) when is_atom(m), do: Atom.to_string(m)
  defp method_string(m) when is_binary(m), do: m

  defp target_string({:abs_path, p}), do: p

  defp target_string({:absoluteURI, scheme, host, port, path}) do
    "#{scheme}://#{host}#{if port == :undefined, do: "", else: ":#{port}"}#{path}"
  end

  defp target_string({:scheme, host, port}), do: "#{host}:#{port}"
  defp target_string(:*), do: "*"
  defp target_string(other) when is_binary(other), do: other

  defp header_string(h) when is_atom(h), do: Atom.to_string(h)
  defp header_string(h) when is_binary(h), do: h
end
