defmodule Managoat.Broker.HTTPTest do
  use ExUnit.Case, async: true

  alias Managoat.Broker.HTTP

  describe "parse_request/1" do
    test "a CONNECT head" do
      raw =
        "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nProxy-Authorization: Basic x\r\n\r\ntail"

      assert {:ok, head, "tail"} = HTTP.parse_request(raw)
      assert head.method == "CONNECT"
      assert head.target == "api.github.com:443"
      assert head.version == {1, 1}
      assert head.headers == [{"Host", "api.github.com:443"}, {"Proxy-Authorization", "Basic x"}]
      assert {:ok, {"api.github.com", 443}, "api.github.com:443"} = HTTP.destination(head)
    end

    test "an absolute-form GET, and its origin-form target" do
      raw =
        "GET http://deb.debian.org/debian/dists/x?y=1 HTTP/1.1\r\nHost: deb.debian.org\r\n\r\n"

      assert {:ok, head, ""} = HTTP.parse_request(raw)
      assert head.method == "GET"
      assert {:ok, {"deb.debian.org", 80}, "/debian/dists/x?y=1"} = HTTP.destination(head)
    end

    test "an absolute-form target with no path is the root" do
      {:ok, head, ""} =
        HTTP.parse_request("GET http://h.example HTTP/1.1\r\nHost: h.example\r\n\r\n")

      assert {:ok, {"h.example", 80}, "/"} = HTTP.destination(head)
    end

    test "only plain HTTP absolute-form targets are accepted outside a tunnel" do
      {:ok, head, ""} =
        HTTP.parse_request("GET https://h.example/x HTTP/1.1\r\nHost: h.example\r\n\r\n")

      assert {:error, :bad_target} = HTTP.destination(head)
    end

    test "an origin-form request inside a tunnel" do
      raw = "POST /repos HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 2\r\n\r\n{}"

      assert {:ok, head, "{}"} = HTTP.parse_request(raw)
      assert head.target == "/repos"
      assert HTTP.body_framing(head) == {:length, 2}
      assert {:error, :bad_target} = HTTP.destination(head)
    end

    test "an incomplete head asks for more, keeping the buffer" do
      assert {:more, _} = HTTP.parse_request("GET /x HTTP/1.1\r\nHost: a")
      assert {:more, _} = HTTP.parse_request("GET /x HT")
    end

    test "garbage is an error" do
      assert {:error, _} = HTTP.parse_request("\x16\x03\x01 not http\r\n\r\n")
    end

    test "a response or malformed header is not accepted as a request" do
      assert {:error, {:unexpected, {:http_response, {1, 1}, 200, "OK"}}} =
               HTTP.parse_request("HTTP/1.1 200 OK\r\n\r\n")

      assert {:error, {:bad_header, _}} =
               HTTP.parse_request("GET / HTTP/1.1\r\n\x00bad\r\n\r\n")
    end

    test "the asterisk request-target is preserved" do
      assert {:ok, %{method: "OPTIONS", target: "*"}, ""} =
               HTTP.parse_request("OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n")
    end

    test "a bad CONNECT authority" do
      {:ok, head, _} = HTTP.parse_request("CONNECT nope HTTP/1.1\r\n\r\n")
      assert {:error, :bad_target} = HTTP.destination(head)

      {:ok, head, _} = HTTP.parse_request("CONNECT h:99999 HTTP/1.1\r\n\r\n")
      assert {:error, :bad_target} = HTTP.destination(head)
    end
  end

  describe "valid_host?/1" do
    test "an ordinary name, an address and a bracketed literal's host all pass" do
      for good <- ["localhost", "api.github.com", "UPPER.Example.com", "127.0.0.1", "::1"] do
        assert HTTP.valid_host?(good), "#{good} was rejected"
      end
    end

    test "the characters that change what something downstream reads" do
      # Each of these reaches `:inet.getaddrs`, SNI, the leaf cache's key
      # and the subject of a certificate this proxy signs. `/` ends the
      # relative distinguished name a leaf's subject is built from.
      for bad <- ["a@b.example", "a/b.example", "a\\b.example", "a?b", "a#b", "a%2fb"] do
        refute HTTP.valid_host?(bad), "#{inspect(bad)} was accepted"
      end
    end

    test "whitespace and control characters" do
      for bad <- ["a b.example", "a\tb.example", "a\rb", "a\nb", "a\0b", "a\x7fb"] do
        refute HTTP.valid_host?(bad), "#{inspect(bad)} was accepted"
      end
    end

    test "length, emptiness and a leading or trailing dot" do
      refute HTTP.valid_host?("")
      refute HTTP.valid_host?(String.duplicate("a", 254))
      assert HTTP.valid_host?(String.duplicate("a", 253))
      refute HTTP.valid_host?(".example.com")
      refute HTTP.valid_host?("example.com.")
    end

    test "anything that is not a binary is not a host" do
      refute HTTP.valid_host?(nil)
      refute HTTP.valid_host?(:localhost)
    end
  end

  describe "destination/1 refuses a host it will not act on" do
    test "on a CONNECT authority" do
      {:ok, head, _} = HTTP.parse_request("CONNECT evil@h.example:443 HTTP/1.1\r\n\r\n")
      assert {:error, :bad_target} = HTTP.destination(head)

      {:ok, head, _} = HTTP.parse_request("CONNECT .h.example:443 HTTP/1.1\r\n\r\n")
      assert {:error, :bad_target} = HTTP.destination(head)
    end

    test "on an absolute-form target" do
      {:ok, head, _} =
        HTTP.parse_request("GET http://h.example./x HTTP/1.1\r\nHost: h.example.\r\n\r\n")

      assert {:error, :bad_target} = HTTP.destination(head)
    end
  end

  test "encode_request round-trips a head with the target substituted" do
    {:ok, head, _} = HTTP.parse_request("GET http://h/p HTTP/1.1\r\nHost: h\r\nX: y\r\n\r\n")

    assert IO.iodata_to_binary(HTTP.encode_request(head, "/p")) ==
             "GET /p HTTP/1.1\r\nHost: h\r\nX: y\r\n\r\n"
  end

  test "body_framing reads chunked before content-length, and none when neither" do
    {:ok, chunked, _} =
      HTTP.parse_request("POST / HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")

    assert HTTP.body_framing(chunked) == :chunked

    {:ok, none, _} = HTTP.parse_request("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    assert HTTP.body_framing(none) == :none
  end

  describe "take_body/2" do
    test "no body" do
      assert {:done, "", "next"} = HTTP.take_body(:none, "next")
    end

    test "content-length, whole and in pieces" do
      assert {:done, "abc", "d"} = HTTP.take_body({:length, 3}, "abcd")
      assert {:partial, "ab", {:length, 1}} = HTTP.take_body({:length, 3}, "ab")
      assert {:done, "c", ""} = HTTP.take_body({:length, 1}, "c")
    end

    test "chunked, forwarded verbatim through to the trailers" do
      body = "3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n"
      assert {:done, ^body, "NEXT"} = HTTP.take_body(:chunked, body <> "NEXT")
    end

    test "chunked, split at every awkward point" do
      body = "3\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: t\r\n\r\n"

      for cut <- 1..(byte_size(body) - 1) do
        <<a::binary-size(cut), b::binary>> = body
        assert {:partial, ^a, state} = HTTP.take_body(:chunked, a)
        assert {:done, ^b, "X"} = HTTP.take_body(state, b <> "X")
      end
    end
  end

  describe "parse_response/1" do
    test "a status line, its headers and the bytes after them" do
      assert {:ok, %{status: 201, reason: "Created", version: {1, 1}, headers: headers}, "body"} =
               HTTP.parse_response("HTTP/1.1 201 Created\r\nContent-Length: 4\r\n\r\nbody")

      assert {"Content-Length", "4"} in headers
    end

    test "a head that has not all arrived yet" do
      assert {:more, "HTTP/1.1 20"} = HTTP.parse_response("HTTP/1.1 20")
    end

    test "a status line that is not one" do
      assert {:error, {:bad_status_line, _}} = HTTP.parse_response("nonsense\r\n\r\n")
    end

    test "a request where a response was expected" do
      # An origin answering a request with a request is not a response with
      # a strange status; it is not a response at all.
      assert {:error, {:unexpected, _}} = HTTP.parse_response("GET / HTTP/1.1\r\n\r\n")
    end
  end

  describe "response_framing/3" do
    test "the method and the status decide before the headers do" do
      assert :none == HTTP.response_framing(200, [{"Content-Length", "5"}], "HEAD")
      assert :none == HTTP.response_framing(100, [{"Content-Length", "5"}], "GET")
      assert :none == HTTP.response_framing(199, [], "GET")
      assert :none == HTTP.response_framing(204, [{"Content-Length", "5"}], "GET")
      assert :none == HTTP.response_framing(304, [{"Content-Length", "5"}], "GET")
    end

    test "otherwise chunked, then content-length, then the close" do
      assert :chunked == HTTP.response_framing(200, [{"Transfer-Encoding", "chunked"}], "GET")
      assert {:length, 5} == HTTP.response_framing(200, [{"Content-Length", "5"}], "GET")
      assert :until_close == HTTP.response_framing(200, [{"Content-Type", "text/html"}], "GET")
    end

    test "a body ended only by the close always wants more" do
      assert {:partial, "abc", :until_close} = HTTP.take_body(:until_close, "abc")
    end
  end
end
