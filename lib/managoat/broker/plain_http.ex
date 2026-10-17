defmodule Managoat.Broker.PlainHTTP do
  @moduledoc false
  # Finch owns the upstream HTTP/1 transport and pooling. Each client has
  # one tagged size-one pool, replaced when its authority/headers or origin
  # change. Tags are digests, never credential values. Idle pools expire even
  # if the client handler is killed before its cleanup runs.
  alias Managoat.Broker.{HTTP, HTTPOnly, Response}
  alias ThousandIsland.Socket

  @key __MODULE__
  @hop_headers ~w(connection proxy-connection keep-alive)

  def eligible?(head, headers) do
    head.method in ["GET", "HEAD"] and HTTP.body_framing(head) in [:none, {:length, 0}] and
      HTTPOnly.check_request(true, head.method, headers) == :ok and
      HTTPOnly.check_framing(true, head.headers, headers) == :ok
  end

  def close(client) do
    case Process.delete(@key) do
      nil -> :ok
      {pool, _address} -> Finch.stop_pool(client, pool)
    end
  end

  # Finch emits connect events in the checked-out connection's caller.
  # Translate only this proxy's scoped context, retaining the existing
  # sanitized origin-connection event (not Finch's request metadata).
  def attach_telemetry do
    :telemetry.attach(
      {__MODULE__, :connect},
      [:finch, :connect, :stop],
      &__MODULE__.connected/4,
      nil
    )
  end

  def connected(_event, _measurements, metadata, _config) do
    case Process.get({__MODULE__, :context}) do
      {client, host, port, meta} when client == metadata.name ->
        failed = Map.has_key?(metadata, :error)
        Process.put({__MODULE__, :connect_failed}, failed)

        :telemetry.execute([:managoat, :broker, :connect], %{count: 1}, %{
          host: host,
          port: port,
          meta: meta,
          outcome: if(failed, do: :upstream_failed, else: :ok)
        })

      _ ->
        :ok
    end
  end

  def request(
        socket,
        {head, headers, target},
        {host, port, addresses},
        session,
        state,
        {pending, emit}
      ) do
    Process.put({__MODULE__, :context}, {state.http_client, host, port, session.meta})

    try do
      do_request(
        socket,
        {head, headers, target},
        {host, port, addresses},
        session,
        state,
        {pending, emit}
      )
    rescue
      _ ->
        emit.({pending, nil, :upstream_send_failed})
        :close
    catch
      :exit, _ ->
        emit.({pending, nil, :upstream_send_failed})
        :close
    after
      Process.delete({__MODULE__, :context})
      Process.delete({__MODULE__, :connect_failed})
    end
  end

  defp do_request(
         socket,
         {head, headers, target},
         {host, port, addresses},
         session,
         state,
         {pending, emit}
       ) do
    tag =
      {self(),
       :crypto.hash(:sha256, :erlang.term_to_binary({host, session, head.headers, headers}))}

    # DNS is resolved and the complete answer set vetted before this call.
    # Prefer the previous address only while it is still eligible for this
    # exact pool identity; resolver ordering must not discard a live socket.
    addresses = prefer_previous(addresses, tag, port)
    selected = hd(addresses)
    address = selected |> :inet.ntoa() |> to_string()
    authority = if tuple_size(selected) == 8, do: "[#{address}]", else: address
    url = "http://#{authority}:#{port}/"
    pool = Finch.Pool.new(url, tag: tag)

    if Process.get(@key) != {pool, selected} do
      close(state.http_client)
      Process.put(@key, {pool, selected})
    end

    # Keep the exact target, including escaping and query bytes. Only the
    # vetted address goes to the transport; the proxy already normalized
    # Host to the absolute target authority after injection.
    request =
      Finch.build(head.method, url, Enum.reject(headers, &hop_header?/1), nil, pool_tag: tag)

    request = %{request | path: target, query: nil}

    acc = %{
      socket: socket,
      head: head,
      status: nil,
      started: false,
      keep: false,
      framing: nil,
      trailers: [],
      framer: Response.expect(Response.new(state.max_response_bytes), pending),
      gate: HTTPOnly.new(true) |> HTTPOnly.expect(head.method),
      emit: emit,
      error: nil
    }

    Process.put({__MODULE__, :connect_failed}, false)

    result =
      Finch.stream_while(request, state.http_client, acc, &receive_part/2,
        receive_timeout: 300_000,
        request_timeout: :infinity,
        pool_timeout: 5_000
      )

    case result do
      {:error, _, _} when length(addresses) > 1 ->
        if Process.get({__MODULE__, :connect_failed}) do
          do_request(
            socket,
            {head, headers, target},
            {host, port, tl(addresses)},
            session,
            state,
            {pending, emit}
          )
        else
          finish_result(result)
        end

      _ ->
        finish_result(result)
    end
  end

  defp prefer_previous(addresses, tag, port) do
    case Process.get(@key) do
      {%Finch.Pool{scheme: :http, port: ^port, tag: ^tag}, address} ->
        if address in addresses, do: [address | List.delete(addresses, address)], else: addresses

      _ ->
        addresses
    end
  end

  defp finish_result(result) do
    case result do
      {:ok, %{error: nil} = acc} -> finish(acc)
      {:ok, acc} -> fail(acc, acc.error)
      {:error, %{reason: :closed}, acc} -> fail(acc, :upstream_closed)
      {:error, _, acc} -> fail(acc, :upstream_read_failed)
    end
  end

  defp receive_part({:status, status}, acc), do: {:cont, %{acc | status: status}}

  defp receive_part({:headers, headers}, acc) do
    framing = HTTP.response_framing(acc.status, headers, acc.head.method)
    keep = acc.head.version == {1, 1} and not close?(acc.head.headers) and framing != :until_close

    headers =
      if acc.status in 100..199 do
        headers
      else
        [
          {"connection", if(keep, do: "keep-alive", else: "close")}
          | Enum.reject(headers, &hop_header?/1)
        ]
      end

    bytes =
      IO.iodata_to_binary([
        "HTTP/1.1 #{acc.status} #{reason_phrase(acc.status)}\r\n",
        Enum.map(headers, fn {k, v} -> [k, ": ", v, "\r\n"] end),
        "\r\n"
      ])

    write(%{acc | framing: framing, keep: keep}, bytes)
  end

  defp receive_part({:data, data}, acc) do
    bytes =
      if acc.framing == :chunked,
        do: IO.iodata_to_binary([Integer.to_string(byte_size(data), 16), "\r\n", data, "\r\n"]),
        else: data

    write(acc, bytes)
  end

  defp receive_part({:trailers, headers}, acc), do: {:cont, %{acc | trailers: headers}}

  defp write(acc, bytes) do
    with {:ok, gate, safe} <- HTTPOnly.filter(acc.gate, bytes),
         :ok <- Socket.send(acc.socket, safe) do
      {framer, finished} = Response.observe(acc.framer, safe)
      Enum.each(finished, acc.emit)
      acc = %{acc | gate: gate, framer: framer, started: true}

      if Response.halted?(framer),
        do: {:halt, %{acc | error: :response_too_large}},
        else: {:cont, acc}
    else
      {:error, reason} -> {:halt, %{acc | error: reason}}
    end
  end

  defp finish(%{framing: :chunked} = acc) do
    bytes =
      IO.iodata_to_binary([
        "0\r\n",
        Enum.map(acc.trailers, fn {k, v} -> [k, ": ", v, "\r\n"] end),
        "\r\n"
      ])

    case write(%{acc | framing: :done}, bytes) do
      {:cont, acc} -> finish(acc)
      {:halt, acc} -> fail(acc, acc.error)
    end
  end

  defp finish(acc) do
    if Response.idle?(acc.framer) and HTTPOnly.idle?(acc.gate) do
      if acc.keep, do: :keep_alive, else: :close
    else
      {_framer, finished} = Response.closed(acc.framer)
      Enum.each(finished, acc.emit)
      :close
    end
  end

  defp fail(acc, reason) do
    unless acc.started or reason == :upstream_closed do
      Socket.send(
        acc.socket,
        "HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-length: 0\r\n\r\n"
      )
    end

    {_framer, finished} = Response.failed(acc.framer, reason)
    Enum.each(finished, acc.emit)
    :close
  end

  defp reason_phrase(100), do: "Continue"
  defp reason_phrase(200), do: "OK"
  defp reason_phrase(_), do: ""

  defp hop_header?({name, _}), do: String.downcase(name) in @hop_headers

  defp close?(headers) do
    Enum.any?(headers, fn {name, value} ->
      String.downcase(name) == "connection" and
        "close" in (value |> String.downcase() |> String.split(",") |> Enum.map(&String.trim/1))
    end)
  end
end
