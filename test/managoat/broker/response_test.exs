defmodule Managoat.Broker.ResponseTest do
  # The framer on its own: which request a response belongs to, what status
  # it carried, and when it ended. Bodies are never its business except as
  # a length to count down.
  use ExUnit.Case, async: true

  alias Managoat.Broker.Response

  # A descriptor is opaque to the framer but for `method`, so these are
  # just enough to tell requests apart.
  defp req(name, method \\ "GET"), do: %{name: name, method: method}

  defp expect(names) when is_list(names) do
    Enum.reduce(names, Response.new(), &Response.expect(&2, &1))
  end

  defp observe(state, data) do
    {state, finished} = Response.observe(state, data)
    {state, Enum.map(finished, fn {r, s, e} -> {r.name, s, e} end)}
  end

  defp names(finished), do: Enum.map(finished, fn {r, s, e} -> {r.name, s, e} end)

  describe "framing one response" do
    test "a fixed-length body ends at the last byte, and the rest is the next response" do
      {state, finished} =
        [req(:a), req(:b)]
        |> expect()
        |> observe("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcHTTP/1.1 404 Nope\r\n")

      assert finished == [{:a, 200, nil}]
      refute Response.idle?(state)

      {_state, finished} = observe(state, "Content-Length: 0\r\n\r\n")
      assert finished == [{:b, 404, nil}]
    end

    test "a chunked body ends at the terminating chunk, trailers included" do
      {state, finished} =
        [req(:a)]
        |> expect()
        |> observe(
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" <>
            "3\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: t\r\n\r\n"
        )

      assert finished == [{:a, 200, nil}]
      assert Response.idle?(state)
    end

    test "a body with neither length nor chunked runs to the close, and ends well there" do
      {state, finished} =
        [req(:a)]
        |> expect()
        |> observe("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nsome bytes")

      assert finished == []

      {_state, finished} = Response.closed(state)
      assert names(finished) == [{:a, 200, nil}]
    end

    test "a HEAD has no body however the response frames itself" do
      {state, finished} =
        [req(:a, "HEAD"), req(:b)]
        |> expect()
        |> observe("HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n")

      assert finished == [{:a, 200, nil}]

      # The next response is the next request's, not 99 bytes of body.
      {_state, finished} = observe(state, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx")
      assert finished == [{:b, 200, nil}]
    end

    test "204 and 304 have no body even carrying a Content-Length" do
      for {status, line} <- [{204, "204 No Content"}, {304, "304 Not Modified"}] do
        {state, finished} =
          [req(:a)]
          |> expect()
          |> observe("HTTP/1.1 #{line}\r\nContent-Length: 42\r\n\r\n")

        assert finished == [{:a, status, nil}]
        assert Response.idle?(state)
      end
    end
  end

  describe "correlation" do
    test "two sequential keep-alive responses go to the right requests" do
      {state, first} =
        [req(:a), req(:b)]
        |> expect()
        |> observe("HTTP/1.1 201 Created\r\nContent-Length: 1\r\n\r\nx")

      {state, second} = observe(state, "HTTP/1.1 500 Boom\r\nContent-Length: 2\r\n\r\nyz")

      assert first == [{:a, 201, nil}]
      assert second == [{:b, 500, nil}]
      assert Response.idle?(state)
    end

    test "two pipelined responses arriving in one packet are attributed in order" do
      {state, finished} =
        [req(:a), req(:b)]
        |> expect()
        |> observe(
          "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx" <>
            "HTTP/1.1 202 Accepted\r\nContent-Length: 1\r\n\r\ny"
        )

      assert finished == [{:a, 200, nil}, {:b, 202, nil}]
      assert Response.idle?(state)
    end

    test "a 1xx does not consume the request; the final response does" do
      {state, finished} =
        [req(:a)]
        |> expect()
        |> observe("HTTP/1.1 100 Continue\r\n\r\n")

      assert finished == []
      refute Response.idle?(state)

      {_state, finished} = observe(state, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
      assert finished == [{:a, 200, nil}]
    end

    test "a response nobody asked for stops framing rather than misattributing" do
      {state, finished} =
        Response.new()
        |> observe("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

      assert finished == []

      # Framing is over: a later request gets no event from these bytes,
      # and `failed/2` is what accounts for it.
      state = Response.expect(state, req(:a))
      {state, finished} = observe(state, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
      assert finished == []

      {_state, finished} = Response.failed(state, :upstream_closed)
      assert names(finished) == [{:a, nil, :upstream_closed}]
    end

    test "bytes split across arbitrary boundaries frame the same" do
      whole =
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" <>
          "HTTP/1.1 204 No Content\r\n\r\n"

      for chunk <- [1, 2, 7, 13] do
        {state, finished} =
          whole
          |> chunks(chunk)
          |> Enum.reduce({expect([req(:a), req(:b)]), []}, fn piece, {state, acc} ->
            {state, finished} = observe(state, piece)
            {state, acc ++ finished}
          end)

        assert finished == [{:a, 200, nil}, {:b, 204, nil}], "split into #{chunk}-byte pieces"
        assert Response.idle?(state)
      end
    end

    defp chunks(binary, size) do
      for <<piece::binary-size(1) <- binary>>, reduce: [] do
        acc -> acc ++ [piece]
      end
      |> Enum.chunk_every(size)
      |> Enum.map(&Enum.join/1)
    end
  end

  describe "the 101 upgrade" do
    test "the upgrade ends its request and stops framing, so frames are never parsed" do
      {state, finished} =
        [req(:a), req(:b)]
        |> expect()
        |> observe("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n")

      assert finished == [{:a, 101, nil}]

      # What follows is WebSocket frames. They must not be read as HTTP,
      # and must not be attributed to anything.
      {_state, finished} = observe(state, <<0x81, 0x02, "hi">>)
      assert finished == []
    end
  end

  describe "endings that are not the response ending" do
    test "an upstream close mid-body carries the status and the terminal error" do
      {state, _} =
        [req(:a)]
        |> expect()
        |> observe("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")

      {_state, finished} = Response.closed(state)
      assert names(finished) == [{:a, 200, :upstream_closed}]
    end

    test "a malformed head fails everything outstanding" do
      {_state, finished} =
        [req(:a), req(:b)]
        |> expect()
        |> observe("this is not a status line\r\n\r\n")

      assert finished == [{:a, nil, :malformed_response}, {:b, nil, :malformed_response}]
    end

    test "a head that never ends is malformed rather than an unbounded buffer" do
      long =
        "HTTP/1.1 200 OK\r\n" <> String.duplicate("X-Pad: #{String.duplicate("p", 90)}\r\n", 800)

      {state, finished} = observe(expect([req(:a)]), long)

      assert finished == [{:a, nil, :malformed_response}]

      # Nothing is still being held, and framing has stopped rather than
      # trying to resynchronise mid-stream.
      assert Response.idle?(state)
      assert {_, []} = observe(state, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    end

    test "failed/2 accounts for the response in flight and everything queued behind it" do
      {state, _} =
        [req(:a), req(:b), req(:c)]
        |> expect()
        |> observe("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort")

      {state, finished} = Response.failed(state, :client_closed)

      assert names(finished) == [
               {:a, 200, :client_closed},
               {:b, nil, :client_closed},
               {:c, nil, :client_closed}
             ]

      assert Response.idle?(state)
    end

    test "a descriptor with no method frames as if the request were not a HEAD" do
      # `request` is opaque to this module but for `method`; one that does
      # not carry it must not be mistaken for a HEAD and lose its body.
      {state, finished} =
        Response.new()
        |> Response.expect(%{name: :a})
        |> observe("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab")

      assert finished == []
      refute Response.idle?(state)

      {state, finished} = observe(state, "c")
      assert finished == [{:a, 200, nil}]
      assert Response.idle?(state)
    end

    test "a close with nothing outstanding says nothing" do
      assert {_, []} = Response.closed(Response.new())
      assert {_, []} = Response.failed(Response.new(), :client_closed)
    end
  end
end
