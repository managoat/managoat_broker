defmodule Managoat.Broker.HTTPOnlyFilterTest do
  use ExUnit.Case, async: true
  alias Managoat.Broker.HTTPOnly

  test "disabled mode is byte-for-byte compatible" do
    assert HTTPOnly.new(false) == nil
    assert HTTPOnly.expect(nil, "GET") == nil
    assert {:ok, nil, "anything"} = HTTPOnly.filter(nil, "anything")
    assert :ok = HTTPOnly.check_request(false, "CONNECT", [{"Upgrade", "websocket"}])
  end

  test "partial heads are held, complete safe heads preserve casing, and bodies stream" do
    gate = gate("GET")
    assert {:ok, gate, ""} = HTTPOnly.filter(gate, "HTTP/1.1 200 OK\r\nX-Case: Value\r\n")
    assert {:ok, gate, bytes} = HTTPOnly.filter(gate, "Content-Length: 8\r\n\r\nfirst")
    assert bytes == "HTTP/1.1 200 OK\r\nX-Case: Value\r\nContent-Length: 8\r\n\r\nfirst"
    assert {:ok, _, "end"} = HTTPOnly.filter(gate, "end")
  end

  test "101 split at every byte boundary never releases a handshake or frames" do
    wire = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nframes"

    for size <- 1..(byte_size(wire) - byte_size("frames") - 1) do
      <<first::binary-size(size), rest::binary>> = wire
      assert {:ok, partial, ""} = HTTPOnly.filter(gate("GET"), first)
      assert {:error, :upstream_upgrade} = HTTPOnly.filter(partial, rest)
    end

    assert {:error, :upstream_upgrade} = HTTPOnly.filter(gate("GET"), wire)
  end

  test "informational heads do not consume the request" do
    first = "HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
    last = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    assert {:ok, _, bytes} = HTTPOnly.filter(gate("GET"), first <> last)
    assert bytes == first <> last

    assert {:error, :upstream_upgrade} =
             HTTPOnly.filter(gate("GET"), first <> "HTTP/1.1 101 Nope\r\n\r\n")
  end

  test "HEAD, empty responses, and pipelined requests preserve response boundaries" do
    gate = gate("HEAD") |> HTTPOnly.expect("GET") |> HTTPOnly.expect("GET")

    bytes =
      "HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n" <>
        "HTTP/1.1 204 No Content\r\n\r\n" <> "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    assert {:ok, _, ^bytes} = HTTPOnly.filter(gate, bytes)
  end

  test "chunked streaming and trailers do not hide the following response" do
    gate = gate("GET") |> HTTPOnly.expect("GET")

    wire =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\nX-Trailer: yes\r\n\r\n"

    {gate, output} =
      for <<byte <- wire>>, reduce: {gate, ""} do
        {state, acc} ->
          assert {:ok, state, safe} = HTTPOnly.filter(state, <<byte>>)
          {state, acc <> safe}
      end

    assert output == wire
    assert {:error, :upstream_upgrade} = HTTPOnly.filter(gate, "HTTP/1.1 101 Nope\r\n\r\n")
  end

  test "close-framed bodies can contain HTTP-looking bytes" do
    head = "HTTP/1.0 200 OK\r\n\r\n"
    assert {:ok, state, ^head} = HTTPOnly.filter(gate("GET"), head)
    assert {:ok, _, "HTTP/1.1 101"} = HTTPOnly.filter(state, "HTTP/1.1 101")
  end

  test "malformed, unsolicited and oversized heads fail closed" do
    assert {:error, :malformed_response} = HTTPOnly.filter(gate("GET"), "not HTTP\r\n\r\n")

    assert {:error, :malformed_response} =
             HTTPOnly.filter(HTTPOnly.new(true), "HTTP/1.1 200 OK\r\n\r\n")

    oversized = "HTTP/1.1 200 OK\r\nX-Large: " <> String.duplicate("x", 65_536)
    assert {:error, :malformed_response} = HTTPOnly.filter(gate("GET"), oversized)
    assert {:error, :malformed_response} = HTTPOnly.filter(gate("GET"), oversized <> "\r\n\r\n")
  end

  for headers <- [
        "Content-Length: -1",
        "Content-Length: 1\r\nContent-Length: 1",
        "Content-Length: 1\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: gzip",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"
      ] do
    test "ambiguous framing #{inspect(headers)} is refused" do
      assert {:error, :malformed_response} =
               HTTPOnly.filter(
                 gate("GET"),
                 "HTTP/1.1 200 OK\r\n" <> unquote(headers) <> "\r\n\r\n"
               )
    end
  end

  test "invalid and unbounded chunk-size/trailer lines fail closed" do
    head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert {:error, :malformed_response} = HTTPOnly.filter(gate("GET"), head <> "not-a-size\r\n")

    assert {:error, :malformed_response} =
             HTTPOnly.filter(gate("GET"), head <> String.duplicate("f", 65_537))

    assert {:error, :malformed_response} =
             HTTPOnly.filter(gate("GET"), head <> "0\r\nX: " <> String.duplicate("x", 65_537))
  end

  for headers <- [
        [{"uPgRaDe", ""}],
        [{"Connection", "keep-alive"}, {"CONNECTION", " close, UpGrAdE "}],
        [{"Proxy-Connection", "upgrade"}]
      ] do
    test "all header occurrences are checked: #{inspect(headers)}" do
      assert {:error, :protocol_upgrade} =
               HTTPOnly.check_request(true, "GET", unquote(Macro.escape(headers)))
    end
  end

  test "invalid header names and value controls cannot manufacture wire headers" do
    for headers <- [
          [{"Bad Name", "value"}],
          [{"X-Test", "value\r\nUpgrade: websocket"}],
          [{"X-Test", <<0>>}]
        ] do
      assert {:error, :unsafe_request} = HTTPOnly.check_request(true, "GET", headers)
    end

    assert :ok = HTTPOnly.check_request(true, "GET", [{"X-Valid", "a\tb"}])
  end

  test "ambiguous request framing and template changes to body boundaries are refused" do
    assert {:error, :unsafe_request} =
             HTTPOnly.check_request(true, "POST", [
               {"Content-Length", "1"},
               {"Content-Length", "2"}
             ])

    assert {:error, :unsafe_request} =
             HTTPOnly.check_request(true, "POST", [
               {"Content-Length", "1"},
               {"Transfer-Encoding", "chunked"}
             ])

    assert {:error, :unsafe_request} =
             HTTPOnly.check_framing(true, [{"Content-Length", "20"}], [{"Content-Length", "0"}])

    assert :ok =
             HTTPOnly.check_framing(true, [{"Content-Length", "020"}], [{"Content-Length", "20"}])

    assert :ok = HTTPOnly.check_framing(false, [], [{"Content-Length", "20"}])
  end

  test "nested CONNECT is refused while normal requests are allowed" do
    assert {:error, :protocol_upgrade} = HTTPOnly.check_request(true, "CONNECT", [])

    assert :ok =
             HTTPOnly.check_request(true, "POST", [
               {"connection", "keep-alive"},
               {"x-test", "upgrade"}
             ])
  end

  defp gate(method), do: true |> HTTPOnly.new() |> HTTPOnly.expect(method)
end
