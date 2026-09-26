defmodule Managoat.Broker.TunnelDenialTest do
  # A `403` inside a CONNECT tunnel refuses the request, not the tunnel,
  # where the refused request left no body behind it and nothing earlier on
  # the tunnel is still being answered. Before this each denial closed its
  # tunnel, and a client that kept asking for refused routes of a host it
  # was otherwise allowed opened a fresh TCP and TLS connection per refusal
  # (managoat/fountain#2503).
  use Managoat.Broker.ProxyCase, async: true

  for http_only <- [false, true] do
    describe "a denial inside a tunnel (http_only: #{http_only})" do
      setup do
        ctx = start_rig()

        session = %Session{
          rules: [
            %Rule{
              name: "allowed",
              pattern: "localhost/allowed",
              scheme: :bearer,
              credential: "tok"
            },
            %Rule{name: "stream", pattern: "localhost/stream", scheme: :bearer, credential: "tok"}
          ],
          unmatched_host_policy: :deny,
          http_only: unquote(http_only),
          expires_at: DateTime.add(DateTime.utc_now(), 600, :second),
          meta: %{}
        }

        token = put_session(ctx, session)
        ctx = Map.merge(ctx, %{token: token, session: session})
        Map.put(ctx, :session, attach_request_telemetry(ctx))
      end

      test "keeps a bodyless request's tunnel, and the next request is injected", ctx do
        tls = tunnel(ctx, ctx.token)
        on_exit(fn -> :ssl.close(tls) end)

        :ok = :ssl.send(tls, "GET /denied HTTP/1.1\r\nHost: localhost\r\n\r\n")
        reply = recv_until(tls, "\r\n\r\n")
        assert reply =~ "HTTP/1.1 403 Forbidden"
        refute reply =~ "connection: close"
        assert reply =~ "content-length: 0"

        {head, echoed} = request(tls, "GET /allowed HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert head =~ "HTTP/1.1 200"
        assert echoed["headers"]["authorization"] == "Bearer tok"

        # And a denial after a relayed response is decided the same way.
        :ok = :ssl.send(tls, "GET /denied-again HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert recv_until(tls, "\r\n\r\n") =~ "HTTP/1.1 403"

        {_, echoed} = request(tls, "GET /allowed/two HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert echoed["headers"]["authorization"] == "Bearer tok"
      end

      test "emits exactly one terminal event per request on a kept tunnel", ctx do
        tls = tunnel(ctx, ctx.token)
        on_exit(fn -> :ssl.close(tls) end)

        :ok = :ssl.send(tls, "GET /denied?q=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        recv_until(tls, "\r\n\r\n")
        request(tls, "GET /allowed HTTP/1.1\r\nHost: localhost\r\n\r\n")

        assert_receive {:request, %{count: 1},
                        %{
                          path: "/denied",
                          method: "GET",
                          status: 403,
                          error: nil,
                          outcome: :denied,
                          rule: nil,
                          scheme: nil
                        }}

        assert_receive {:request, _,
                        %{path: "/allowed", status: 200, error: nil, outcome: :injected}}

        refute_receive {:request, _, %{path: "/denied"}}, 200
      end

      test "keeps the tunnel for a declared body of zero bytes", ctx do
        tls = tunnel(ctx, ctx.token)
        on_exit(fn -> :ssl.close(tls) end)

        :ok =
          :ssl.send(tls, "POST /denied HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")

        reply = recv_until(tls, "\r\n\r\n")
        assert reply =~ "HTTP/1.1 403"
        refute reply =~ "connection: close"

        {_, echoed} = request(tls, "GET /allowed HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert echoed["headers"]["authorization"] == "Bearer tok"
      end

      for {label, body} <- [
            {"a declared length", "Content-Length: 4\r\n\r\nbody"},
            {"a chunked body", "Transfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"}
          ] do
        test "closes the tunnel when the refused request carried #{label}", ctx do
          # The proxy does not read a body it is refusing, so the next head
          # could not be found in the stream.
          tls = tunnel(ctx, ctx.token)

          :ok = :ssl.send(tls, "POST /denied HTTP/1.1\r\nHost: localhost\r\n" <> unquote(body))

          reply = recv_until(tls, "\r\n\r\n")
          assert reply =~ "HTTP/1.1 403"
          assert reply =~ "connection: close"
          assert {:error, :closed} = :ssl.recv(tls, 0, 2_000)

          assert_receive {:request, _, %{path: "/denied", status: 403, outcome: :denied}}
          refute_receive {:request, _, %{path: "/denied"}}, 200
        end
      end

      test "closes instead of answering inside a response still on its way", ctx do
        # Pipelined behind a stream the origin has not finished, the proxy's
        # own reply could only land in the middle of it. So the tunnel is not
        # kept, as before.
        tls = tunnel(ctx, ctx.token)
        name = "denial_stream_#{System.unique_integer([:positive])}"

        :ok =
          :ssl.send(
            tls,
            "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{name}\r\n\r\n" <>
              "GET /denied HTTP/1.1\r\nHost: localhost\r\n\r\n"
          )

        wire = read_until_tls_closed(tls)
        assert wire =~ "HTTP/1.1 403 Forbidden\r\nconnection: close\r\n"

        assert_receive {:request, _, %{path: "/denied", status: 403, outcome: :denied}}
        assert_receive {:request, _, %{path: "/stream", error: :client_closed}}
        refute_receive {:request, _, %{path: "/denied"}}, 200
      end
    end
  end

  defp read_until_tls_closed(tls, acc \\ "") do
    case :ssl.recv(tls, 0, 5_000) do
      {:ok, data} -> read_until_tls_closed(tls, acc <> data)
      {:error, :closed} -> acc
    end
  end
end
