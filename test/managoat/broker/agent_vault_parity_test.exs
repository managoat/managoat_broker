defmodule Managoat.Broker.AgentVaultParityTest do
  # The behaviours Fountain relied on from Agent Vault 0.39.1, replayed
  # against this proxy. Each test names the upstream test it stands in for
  # (internal/mitm/proxy_test.go and forward_test.go in
  # Infisical/agent-vault), so a gap between the two is a missing test here,
  # not a guess. What is deliberately NOT ported is listed at the bottom.
  use Managoat.Broker.ProxyCase, async: true

  setup do
    ctx = start_rig()

    session = %Session{
      rules: [
        %Rule{name: "origin", pattern: "localhost", scheme: :bearer, credential: "real-secret"}
      ],
      unmatched_host_policy: :passthrough,
      expires_at: DateTime.add(DateTime.utc_now(), 600, :second),
      meta: %{conversation_id: "conv-parity"}
    }

    Map.merge(ctx, %{token: put_session(ctx, session), session: session})
  end

  defp read_json(tls, acc \\ "") do
    {:ok, data} = :ssl.recv(tls, 0, 5_000)
    acc = acc <> data

    with [head, body] <- String.split(acc, "\r\n\r\n", parts: 2),
         [_, len] <- Regex.run(~r/content-length: (\d+)/i, head),
         true <- byte_size(body) >= String.to_integer(len) do
      Jason.decode!(binary_part(body, 0, String.to_integer(len)))
    else
      _ -> read_json(tls, acc)
    end
  end

  # TestMITMInjectsCredentials
  test "the credential is attached where the client sent a placeholder", ctx do
    tls = tunnel(ctx, ctx.token)

    :ok =
      :ssl.send(
        tls,
        "GET /a HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer __key__\r\n\r\n"
      )

    assert %{"headers" => %{"authorization" => "Bearer real-secret"}} = read_json(tls)
  end

  # TestMITMForwardStripsHopByHopHeaders / TestMITMBearerForwardsArbitraryClientHeaders
  test "proxy headers are stripped; every other client header is forwarded", ctx do
    tls = tunnel(ctx, ctx.token)

    :ok =
      :ssl.send(
        tls,
        "GET /h HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Basic leak\r\n" <>
          "Proxy-Connection: keep-alive\r\nX-Custom: yes\r\nUser-Agent: sandbox/1\r\n\r\n"
      )

    %{"headers" => headers} = read_json(tls)
    refute Map.has_key?(headers, "proxy-authorization")
    refute Map.has_key?(headers, "proxy-connection")
    assert headers["x-custom"] == "yes"
    assert headers["user-agent"] == "sandbox/1"
  end

  # TestMITMForwardKeepalivePersistsAcrossRequests
  test "keep-alive: the injection happens on every request of a tunnel", ctx do
    tls = tunnel(ctx, ctx.token)

    for n <- 1..3 do
      :ok = :ssl.send(tls, "GET /#{n} HTTP/1.1\r\nHost: localhost\r\n\r\n")
      path = "/#{n}"

      assert %{"path" => ^path, "headers" => %{"authorization" => "Bearer real-secret"}} =
               read_json(tls)
    end
  end

  # TestMITMForwardStreamsChunksPromptly
  test "a streaming response is relayed chunk by chunk, not buffered to the end", ctx do
    tls = tunnel(ctx, ctx.token)
    stream = "parity_stream_#{System.unique_integer([:positive])}"

    :ok =
      :ssl.send(
        tls,
        "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{stream}\r\n\r\n"
      )

    first = recv_until(tls, "data: first")
    refute first =~ "data: second"

    # Release the origin's second chunk and see it arrive.
    send(String.to_atom(stream), :continue)

    assert recv_until(tls, "data: second") =~ "data: second"
  end

  # TestMITMUpstreamCertUntrusted
  test "an origin whose certificate is not trusted is a 502, and no tunnel opens", ctx do
    {_tcp, reply} = connect(ctx, "localhost:#{ctx.untrusted_port}", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 502"
  end

  # TestMITMPassthroughForwardsClientAuthorization
  test "an unmatched host keeps the client's own authorization header", ctx do
    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: []})
    tls = tunnel(ctx, ctx.token)

    :ok =
      :ssl.send(tls, "GET /p HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer mine\r\n\r\n")

    assert %{"headers" => %{"authorization" => "Bearer mine"}} = read_json(tls)
  end

  # TestMITMUnknownHostInTunnel (deny mode)
  test "deny: an unmatched host is 403 inside the tunnel", ctx do
    # A rule for one path of the host lets the tunnel open; the request
    # below is to another path, so it is unmatched inside the tunnel.
    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [%Rule{name: "narrow", pattern: "localhost/allowed/*", scheme: :passthrough}],
        unmatched_host_policy: :deny
    })

    tls = tunnel(ctx, ctx.token)
    :ok = :ssl.send(tls, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    {:ok, reply} = :ssl.recv(tls, 0, 5_000)
    assert reply =~ "HTTP/1.1 403"
  end

  # Beyond Agent Vault, for a `limited` network policy: under deny a host no
  # rule names is refused at CONNECT, so no tunnel and no TLS handshake
  # happen for it.
  test "deny: a host no rule names is 403 at CONNECT", ctx do
    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [%Rule{name: "x", pattern: "api.example.com", scheme: :passthrough}],
        unmatched_host_policy: :deny
    })

    {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 403"
  end

  # TestMITMMissingProxyAuth / TestMITMInvalidSession
  test "no token and a bad token are refused with 407", ctx do
    for auth <- [nil, proxy_auth("mb_bad")] do
      {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", auth)
      assert reply =~ "HTTP/1.1 407"
    end
  end

  # TestMITMWebSocketInjectsCredentialsAndPipesFrames (the header half: the
  # upgrade request is injected like any other; frames are piped as bytes,
  # never rewritten, see the list at the bottom)
  test "a WebSocket upgrade through the tunnel carries the injected header, and frames flow",
       ctx do
    tls = tunnel(ctx, ctx.token)
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    :ok =
      :ssl.send(
        tls,
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" <>
          "Sec-WebSocket-Key: #{key}\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer __key__\r\n\r\n"
      )

    {:ok, reply} = :ssl.recv(tls, 0, 5_000)
    assert reply =~ "HTTP/1.1 101"

    # One masked text frame: "hi".
    mask = <<1, 2, 3, 4>>
    payload = :crypto.exor("hi", binary_part(mask, 0, 2))
    :ok = :ssl.send(tls, <<0x81, 0x82>> <> mask <> payload)

    {:ok, frame} = :ssl.recv(tls, 0, 5_000)
    <<0x81, len, text::binary-size(len)>> = frame
    assert text == "Bearer real-secret|hi"
  end

  # TestMITMSubstitutionPath / TestMITMSubstitutionQuery, and the `telegram`
  # preset those tests exercise: a bot API carries its token in the URL, so
  # a substitution that reached headers only could not broker it at all.
  test "a placeholder in the path and in the query is substituted in the forwarded target",
       ctx do
    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | rules: [
          %Rule{
            name: "telegram",
            pattern: "localhost",
            scheme: :substitute,
            placeholder: "__bot_token__",
            credential: "123456:AAE-real"
          }
        ]
    })

    tls = tunnel(ctx, ctx.token)

    :ok =
      :ssl.send(
        tls,
        "GET /bot__bot_token__/sendMessage?key=__bot_token__ HTTP/1.1\r\n" <>
          "Host: localhost\r\n\r\n"
      )

    echoed = read_json(tls)

    # Agent Vault substituted wherever the placeholder appeared, without
    # being told which URI component it was in.
    assert echoed["path"] == "/bot123456:AAE-real/sendMessage"
    assert echoed["query"] == "key=123456:AAE-real"
  end

  # Agent Vault emitted its request record after `io.Copy` completed, with
  # a latency measured from handler entry through response-body completion.
  # This proxy frames responses for the same reason, so its one request
  # event is terminal too.
  test "the request event is emitted when the response ends, with its status", ctx do
    session = attach_request_telemetry(ctx)
    Memory.put(ctx.store, ctx.token, session)

    tls = tunnel(ctx, ctx.token)
    stream = "parity_terminal_#{System.unique_integer([:positive])}"

    :ok =
      :ssl.send(
        tls,
        "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{stream}\r\n\r\n"
      )

    # Agent Vault's latency was total duration, not time to first byte, so
    # the record does not exist yet even though bytes have arrived.
    recv_until(tls, "data: first")
    refute_receive {:request, _, _}, 100

    send(String.to_atom(stream), :continue)
    recv_until(tls, "data: second")

    assert_receive {:request, %{count: 1, duration: duration},
                    %{path: "/stream", status: 200, error: nil}}

    assert System.convert_time_unit(duration, :native, :millisecond) >= 0
  end

  # Not ported, and each one a decision rather than a backlog item. Agent
  # Vault is deleted from the cluster and from Fountain's codebase, so the
  # A/B that settled the last round — the same request against both
  # proxies, compared on the wire — no longer exists. Reopening a row here
  # means arguing it from the upstream tests above, from v0.39.1's source
  # or from the protocol, because it can no longer be measured. README.md's
  # "Deviations from Agent Vault" is the prose version.
  #
  # Expected to stay divergent:
  #
  # - TestMITM*RateLimit* (auth-failure rate limiting on the proxy port).
  #   Having one caused a production incident: it counted per source
  #   address, every sandbox behind one NAT egress shared an address, and
  #   one misconfigured client locked out unrelated tenants. Not having it
  #   is the fix. What replaces it is an operational assumption the host
  #   holds up — the listener is reachable only through the intended
  #   ingress — and if that stops being true the answer is a limiter keyed
  #   on something better than the peer address, not this one back.
  # - TestMITMVaultHintMismatch: Agent Vault refused a valid token
  #   presented with another vault's name. Here the token is random and is
  #   the whole binding, so the label half of the proxy credential is not
  #   consulted and there is no mismatch to test; the label exists only
  #   because some clients (git) refuse a proxy URL with a user and no
  #   password. proxy_test.exs asserts the label is ignored.
  # - TestCopyWSFrames* (credential substitution inside WebSocket frames).
  #   Rewriting frames replaces a byte pipe with a protocol implementation
  #   that has to get masking, fragmentation, control-frame interleaving
  #   and negotiated compression right before a substitution is correct,
  #   and nothing sends a credential inside a frame today.
  # - TestResponseLimit* (response-body cap): not a parity gap at all.
  #   Agent Vault's response cap was unlimited by default, so there is
  #   nothing to match; a cap would be new protection on its own terms.
  # - TestMITMPortBasedRouting, TestMITMAmbiguousAgentVault: Agent Vault's
  #   multi-vault selection, which a per-conversation token makes moot.
  #
  # Divergent for now, with a condition attached:
  #
  # - Plain-HTTP client keep-alive. `forward_plain/8` sends `Connection:
  #   close` upstream and closes after the response. Supporting keep-alive
  #   is not just dropping that header: successive absolute-form requests
  #   on one connection may name different origins, so auth and session
  #   reuse must stay well-defined. No consumer needs it; if one does it
  #   gets its own issue and acceptance tests.
  # - TestRequestBodyCap* (request-body cap). This one *is* a real parity
  #   gap: v0.39.1 capped request bodies at 1 GiB by default. This proxy
  #   streams request bodies rather than materialising them, so the
  #   memory-exhaustion rationale is weaker, but an authenticated client
  #   can still occupy a connection indefinitely. Deferred until that
  #   protection is wanted, and not called parity in the meantime.
  # - TestMITMSubstitutionBody (placeholder rewriting inside a request
  #   body): the `:substitute` rule reaches header values and the request
  #   target, so a credential in a header, a path or a query is brokered,
  #   but a body is still forwarded as bytes.
end
