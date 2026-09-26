defmodule Managoat.Broker.ProtectedProxyTest do
  use Managoat.Broker.ProxyCase, async: true
  alias Managoat.Broker.{ProtectedCredential, ProtectedRule}

  defmodule ProtectedStore do
    @behaviour Managoat.Broker.Store
    @impl true
    def lookup(store, token), do: Memory.lookup(store, token)
    @impl true
    def authorize({state, generation}, request) do
      data = Agent.get(state, & &1)
      send(data.owner, {:authorize, request})

      cond do
        data.generation != generation -> {:error, :denied}
        Map.get(request, :protected, false) -> respond(data.result)
        true -> {:ok, data.rules}
      end
    end

    @impl true
    def authorize(_instance, ref, request), do: authorize(ref, request)
    defp respond({:raise, value}), do: raise(value)
    defp respond({:exit, value}), do: exit(value)
    defp respond({:throw, value}), do: throw(value)
    defp respond(value), do: value
  end

  # The origin tells this process what it saw (`/report`) instead of echoing
  # it at the client: an echo of a protected request repeats its bearer,
  # which is exactly what the proxy now refuses to relay. One name serves
  # the module because a module's tests run one at a time.
  @observer :protected_proxy_test_observer

  setup do
    Process.register(self(), @observer)
    ctx = start_rig(store_module: ProtectedStore)

    policy = %ProtectedRule{
      host: "localhost",
      port: ctx.https_port,
      paths: ["/allowed", "/stream", "/report", "/reflect/", "/sse"],
      methods: ["GET", "POST"],
      identity: "account-1",
      identity_header: "x-account-id",
      allowed_headers: ["content-type", "x-stream-name", "x-report-to", "accept-encoding"],
      name: "managed"
    }

    owner = self()
    credential = %ProtectedCredential{bearer: "managed-secret", identity: "account-1"}

    state =
      start_supervised!(
        {Agent, fn -> %{owner: owner, generation: 1, result: {:ok, credential}, rules: []} end}
      )

    session = %Session{
      protected: policy,
      http_only: true,
      authorization: {state, 1},
      unmatched_host_policy: :deny
    }

    token = put_session(ctx, session)
    session = attach_request_telemetry(Map.merge(ctx, %{token: token, session: session}))
    Map.merge(ctx, %{policy: policy, state: state, token: token, session: session})
  end

  test "the protected path resolves and injects its bearer and pinned identity", ctx do
    tls = tunnel(ctx, ctx.token)
    on_exit(fn -> :ssl.close(tls) end)

    {_, %{"reported" => true}} =
      request(
        tls,
        "GET /report HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: fake\r\nX-Account-ID: another\r\nCookie: identity=another\r\nX-Forwarded-Host: attacker.example\r\nContent-Type: application/json\r\nAccept-Encoding: gzip, br\r\nX-Report-To: #{@observer}\r\n\r\n"
      )

    assert_receive {:origin_saw, %{headers: headers}}
    assert headers["authorization"] == "Bearer managed-secret"
    assert headers["x-account-id"] == "account-1"
    assert headers["host"] == "localhost:#{ctx.https_port}"
    assert headers["content-type"] == "application/json"
    # Allowlisted or not, the client does not choose the response's coding.
    assert headers["accept-encoding"] == "identity"
    refute Map.has_key?(headers, "cookie")
    refute Map.has_key?(headers, "x-forwarded-host")
    assert_receive {:authorize, %{protected: true, target: "/report"}}
    assert_receive {:request, _, %{scheme: :protected_bearer}}
  end

  test "rotation and revocation affect requests inside the same tunnel", ctx do
    tls = tunnel(ctx, ctx.token)
    request(tls, raw("/report"))
    assert_receive {:origin_saw, %{headers: %{"authorization" => "Bearer managed-secret"}}}

    Agent.update(
      ctx.state,
      &%{&1 | result: {:ok, %ProtectedCredential{bearer: "rotated", identity: "account-1"}}}
    )

    request(tls, raw("/report"))
    assert_receive {:origin_saw, %{headers: %{"authorization" => "Bearer rotated"}}}
    Agent.update(ctx.state, &%{&1 | generation: 2})
    assert_refused(tls, "/allowed", 403)
  end

  for failure <- [:unavailable, :raise, :exit, :throw, :wrong_identity, :ordinary_rules] do
    test "#{failure} never falls back to cached credentials", ctx do
      tls = tunnel(ctx, ctx.token)
      request(tls, raw("/report"))
      Agent.update(ctx.state, &%{&1 | result: failure(unquote(failure))})
      log = ExUnit.CaptureLog.capture_log(fn -> assert_refused(tls, "/allowed", 503) end)
      refute log =~ "secret-in-error"
      assert_receive {:request, _, %{status: 503, error: :authorization_unavailable} = meta}
      refute inspect(meta) =~ "secret-in-error"
    end
  end

  test "ordinary injection and template aliases cannot export or shadow the managed bearer",
       ctx do
    # A separate destination can use ordinary secrets. The protected value
    # is never part of the map the custom renderer receives, even under an alias.
    rule = %Rule{
      pattern: "127.0.0.1",
      scheme: :custom,
      credential: %{"OTHER" => "ordinary-secret"},
      template: %{"X-Own" => "{{ OTHER }}", "Authorization" => "Bearer {{ MANAGED }}"}
    }

    Agent.update(ctx.state, &%{&1 | rules: [rule]})

    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | unmatched_host_policy: :passthrough,
        rules: [rule]
    })

    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :gen_tcp.send(tcp, plain(ctx, "127.0.0.1", ctx.http_port))
    {_, body} = read_plain_json(tcp)
    assert body["headers"]["x-own"] == "ordinary-secret"
    assert body["headers"]["authorization"] == "Bearer {{ MANAGED }}"
    refute inspect(body) =~ "managed-secret"
    assert_receive {:authorize, req}
    refute Map.has_key?(req, :protected)
    :gen_tcp.close(tcp)

    conflict = %{rule | pattern: "localhost", template: %{"Upgrade" => "websocket"}}
    Memory.put(ctx.store, ctx.token, %{ctx.session | rules: [conflict]})
    tls = tunnel(ctx, ctx.token)
    assert_refused(tls, "/allowed", 403)
    refute_received {:authorize, %{protected: true}}
    assert_receive {:request, _, %{error: :protected_conflict}}
  end

  test "wrong paths and cleartext or alternate ports cannot resolve the bearer", ctx do
    for path <- ["/other", "/allowed/suffix", "/allowed%2f..", "/allowed/../other"] do
      tls = tunnel(ctx, ctx.token)
      assert_refused(tls, path, 403)
    end

    for port <- [ctx.http_port, ctx.https_port] do
      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
      :gen_tcp.send(tcp, plain(ctx, "localhost", port))
      assert read_until_closed(tcp) =~ "403 Forbidden"
    end

    refute_received {:authorize, _}
  end

  test "unapproved HTTP methods cannot resolve a credential", ctx do
    tls = tunnel(ctx, ctx.token)
    :ssl.send(tls, "TRACE /allowed HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
    refute_received {:authorize, _}
    :ssl.close(tls)
  end

  test "invalid persisted policy is refused before opening a tunnel", ctx do
    Memory.put(ctx.store, ctx.token, %{ctx.session | http_only: false})
    {tcp, response} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
    assert response =~ "407"
    :gen_tcp.close(tcp)
    refute_received {:authorize, _}
  end

  test "raw upgrade and chunked request trailers are denied before bearer resolution", ctx do
    for headers <- ["Upgrade: websocket\r\n", "Transfer-Encoding: chunked\r\n"] do
      tls = tunnel(ctx, ctx.token)
      :ssl.send(tls, raw("/allowed", headers))
      assert recv_until(tls, "\r\n\r\n") =~ "403 Forbidden"
      :ssl.close(tls)
    end

    refute_received {:authorize, _}
  end

  test "streamed responses finish across revocation but the next request is refused", ctx do
    tls = tunnel(ctx, ctx.token)
    name = "protected_stream_#{System.unique_integer([:positive])}"
    :ssl.send(tls, raw("/stream", "X-Stream-Name: #{name}\r\n"))
    assert recv_until(tls, "data: first") =~ "200"
    Agent.update(ctx.state, &%{&1 | generation: 2})
    send(String.to_existing_atom(name), :continue)
    assert recv_until(tls, "0\r\n\r\n") =~ "data: second"
    assert_refused(tls, "/allowed", 403)
  end

  test "protected TLS cannot disable certificate validation through listener overrides" do
    ctx =
      start_rig(
        upstream_ssl_options: [
          verify: :verify_none,
          verify_fun: {fn _, _, state -> {:valid, state} end, nil}
        ]
      )

    policy = %ProtectedRule{
      host: "localhost",
      port: ctx.untrusted_port,
      paths: ["/allowed"],
      methods: ["GET", "POST"],
      identity: "id",
      identity_header: "x-id",
      allowed_headers: []
    }

    token = put_session(ctx, %Session{protected: policy, http_only: true, authorization: :ref})

    for host <- ["localhost", "LOCALHOST"] do
      {tcp, response} = connect(ctx, "#{host}:#{ctx.untrusted_port}", proxy_auth(token))
      assert response =~ "502 Bad Gateway"
      :gen_tcp.close(tcp)
    end
  end

  test "protected TLS uses the actual destination name despite listener SNI overrides" do
    ctx =
      start_rig(
        store_module: ProtectedStore,
        upstream_ssl_options: [
          server_name_indication: ~c"wrong.example",
          customize_hostname_check: [match_fun: fn _, _ -> true end]
        ]
      )

    owner = self()

    state =
      start_supervised!(
        {Agent,
         fn ->
           %{
             owner: owner,
             generation: 1,
             rules: [],
             result: {:ok, %ProtectedCredential{bearer: "verified", identity: "id"}}
           }
         end},
        id: make_ref()
      )

    policy = %ProtectedRule{
      host: "localhost",
      port: ctx.https_port,
      paths: ["/report"],
      methods: ["GET", "POST"],
      identity: "id",
      identity_header: "x-id",
      allowed_headers: ["x-report-to"]
    }

    token =
      put_session(ctx, %Session{protected: policy, http_only: true, authorization: {state, 1}})

    tls = tunnel(ctx, token)
    request(tls, raw("/report"))
    assert_receive {:origin_saw, %{headers: %{"authorization" => "Bearer verified"}}}
    :ssl.close(tls)
  end

  test "redirects never carry the protected bearer to the next destination", ctx do
    policy = %{ctx.policy | paths: ["/redirect"], allowed_headers: ["x-redirect-to"]}

    Memory.put(ctx.store, ctx.token, %{
      ctx.session
      | protected: policy,
        unmatched_host_policy: :passthrough
    })

    tls = tunnel(ctx, ctx.token)
    destination = "http://127.0.0.1:#{ctx.http_port}/allowed"
    {head, %{}} = request(tls, raw("/redirect", "X-Redirect-To: #{destination}\r\n"))
    assert head =~ "302"
    assert head =~ destination
    assert_receive {:authorize, %{protected: true}}
    refute_received {:authorize, _}
    :ssl.close(tls)
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :gen_tcp.send(tcp, plain(ctx, "127.0.0.1", ctx.http_port))
    {_, body} = read_plain_json(tcp)
    refute Map.has_key?(body["headers"], "authorization")
    refute inspect(body) =~ "managed-secret"
    :gen_tcp.close(tcp)
  end

  test "a trusted certificate for the wrong host is still refused" do
    {ca, tls_opts} = origin_tls_for_address(<<192, 0, 2, 1>>)

    ctx =
      start_rig(
        extra_cacerts: [X509.Certificate.to_der(ca)],
        upstream_ssl_options: [customize_hostname_check: [match_fun: fn _, _ -> true end]]
      )

    port = start_https_origin(tls_opts)

    policy = %ProtectedRule{
      host: "localhost",
      port: port,
      paths: ["/allowed"],
      methods: ["GET"],
      identity: "id",
      identity_header: "x-id",
      allowed_headers: []
    }

    token = put_session(ctx, %Session{protected: policy, http_only: true, authorization: :ref})
    {tcp, response} = connect(ctx, "localhost:#{port}", proxy_auth(token))
    assert response =~ "502 Bad Gateway"
    :gen_tcp.close(tcp)
  end

  describe "a query on a protected route" do
    test "the exact route passes and any query is refused before the bearer is resolved", ctx do
      tls = tunnel(ctx, ctx.token)
      request(tls, raw("/report"))
      assert_receive {:origin_saw, %{path: "/report", query: ""}}
      assert_receive {:authorize, %{protected: true}}
      assert_receive {:request, _, %{status: 200, error: nil}}
      :ssl.close(tls)

      for target <- ["/report?x=1", "/report?"] do
        tls = tunnel(ctx, ctx.token)
        assert_refused(tls, target, 403)

        assert_receive {:request, _,
                        %{
                          status: 403,
                          error: :protected_query,
                          outcome: :denied,
                          scheme: nil,
                          path: "/report"
                        }}
      end

      # No credential was asked for, and the origin never heard of either.
      refute_received {:authorize, _}
      refute_received {:origin_saw, _}
    end

    test "a policy that allows queries forwards one unchanged under the bearer", ctx do
      Memory.put(ctx.store, ctx.token, %{
        ctx.session
        | protected: %{ctx.policy | query: :allow}
      })

      tls = tunnel(ctx, ctx.token)
      request(tls, raw("/report?model=x&y="))

      assert_receive {:origin_saw,
                      %{
                        query: "model=x&y=",
                        headers: %{"authorization" => "Bearer managed-secret"}
                      }}
    end

    test "a query to any other destination is none of the protected rule's business", ctx do
      rule = %Rule{name: "plain", pattern: "127.0.0.1", scheme: :bearer, credential: "ordinary"}
      Agent.update(ctx.state, &%{&1 | rules: [rule]})
      Memory.put(ctx.store, ctx.token, %{ctx.session | rules: [rule]})

      tls = address_tunnel(ctx)
      {_, body} = request(tls, "GET /anything?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
      assert body["query"] == "x=1"
      assert body["headers"]["authorization"] == "Bearer ordinary"
    end
  end

  describe "per-route policy" do
    # Two routes under one bearer, shaped like the Codex pair: a POST that
    # takes no query, and a GET that takes one pinned parameter.
    setup ctx do
      policy = %{
        ctx.policy
        | paths: nil,
          methods: nil,
          routes: [
            %{path: "/report", methods: ["POST"], query: :refuse},
            %{path: "/report/models", methods: ["GET"], query: {:only, ["client_version"]}},
            %{path: "/reflect/", methods: ["GET"], query: {:only, ["client_version"]}}
          ]
      }

      Memory.put(ctx.store, ctx.token, %{ctx.session | protected: policy})
      %{routed: policy}
    end

    test "the narrow route admits its pinned parameter under the bearer", ctx do
      tls = tunnel(ctx, ctx.token)

      {_, %{"reported" => true}} =
        request(
          tls,
          raw(
            "/report/models?client_version=0.44.0",
            "Authorization: fake\r\nX-Account-ID: another\r\nCookie: a=b\r\nAccept-Encoding: gzip\r\n"
          )
        )

      assert_receive {:origin_saw,
                      %{method: "GET", path: "/report/models", query: "client_version=0.44.0"} =
                        saw}

      assert saw.headers["authorization"] == "Bearer managed-secret"
      assert saw.headers["x-account-id"] == "account-1"
      assert saw.headers["accept-encoding"] == "identity"
      refute Map.has_key?(saw.headers, "cookie")

      assert_receive {:authorize,
                      %{protected: true, target: "/report/models?client_version=0.44.0"}}

      assert_receive {:request, _,
                      %{
                        status: 200,
                        rule: "managed",
                        scheme: :protected_bearer,
                        path: "/report/models"
                      }}

      # The same tunnel carries the wide route next, under its own policy.
      {_, %{"reported" => true}} = request(tls, post("/report"))
      assert_receive {:origin_saw, %{method: "POST", path: "/report", query: ""} = saw}
      assert saw.headers["authorization"] == "Bearer managed-secret"
      :ssl.close(tls)
    end

    test "another parameter, another route's method or a query off the list is refused", ctx do
      refusals = [
        {raw("/report/models?model=x"), :protected_query},
        {raw("/report/models?client_version=1&model=x"), :protected_query},
        {raw("/report/models?client_version=1&client_version=2"), :protected_query},
        {raw("/report/models?client_version=%0d%0a"), :protected_query},
        {post("/report?client_version=1"), :protected_query},
        {post("/report/models"), :protected_destination},
        {raw("/report"), :protected_destination},
        {raw("/report/other"), :protected_destination}
      ]

      for {head, error} <- refusals do
        tls = tunnel(ctx, ctx.token)
        :ssl.send(tls, head)
        assert recv_until(tls, "\r\n\r\n") =~ "HTTP/1.1 403", head
        assert_receive {:request, _, %{status: 403, error: ^error, outcome: :denied}}
        :ssl.close(tls)
      end

      refute_received {:authorize, _}
      refute_received {:origin_saw, _}
    end

    test "an ordinary rule on either route conflicts before the bearer is resolved", ctx do
      rule = %Rule{pattern: "localhost/report/models", scheme: :bearer, credential: "ordinary"}
      Agent.update(ctx.state, &%{&1 | rules: [rule]})

      Memory.put(ctx.store, ctx.token, %{
        ctx.session
        | protected: ctx.routed,
          rules: [rule]
      })

      tls = tunnel(ctx, ctx.token)
      :ssl.send(tls, raw("/report/models?client_version=1"))
      assert recv_until(tls, "\r\n\r\n") =~ "HTTP/1.1 403"
      assert_receive {:request, _, %{error: :protected_conflict}}
      refute_received {:authorize, %{protected: true}}
      refute_received {:origin_saw, _}
      :ssl.close(tls)
    end

    test "a response on a routed request is still searched for the bearer", ctx do
      tls = tunnel(ctx, ctx.token)
      :ssl.send(tls, raw("/reflect/body?client_version=1"))
      response = read_until_tls_closed(tls)
      assert response =~ "HTTP/1.1 502 Bad Gateway"
      refute response =~ "managed-secret"
      assert_receive {:request, _, %{error: :credential_reflected, rule: "managed"}}
    end

    test "an upgrade on a routed request is refused before the bearer is resolved", ctx do
      tls = tunnel(ctx, ctx.token)
      :ssl.send(tls, raw("/report/models?client_version=1", "Upgrade: websocket\r\n"))
      assert recv_until(tls, "\r\n\r\n") =~ "HTTP/1.1 403"
      refute_received {:authorize, _}
      :ssl.close(tls)
    end

    test "a malformed route is refused before a tunnel opens", ctx do
      broken = %{ctx.routed | routes: [%{path: "/report", methods: ["TRACE"]}]}
      Memory.put(ctx.store, ctx.token, %{ctx.session | protected: broken})
      {tcp, response} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(ctx.token))
      assert response =~ "407"
      :gen_tcp.close(tcp)
    end
  end

  describe "a protected response that repeats its bearer" do
    test "in a header is answered with a fixed 502, and says so without saying what", ctx do
      tls = tunnel(ctx, ctx.token)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          :ssl.send(tls, raw("/reflect/header"))
          response = read_until_tls_closed(tls)
          assert response =~ "HTTP/1.1 502 Bad Gateway"
          assert response =~ "The broker refused the upstream response."
          refute response =~ "managed-secret"
          refute response =~ "x-debug-authorization"
        end)

      assert_receive {:request, _, %{status: 502, error: :credential_reflected} = meta}
      assert meta.path == "/reflect/header"
      assert meta.rule == "managed"
      assert meta.scheme == :protected_bearer

      # The line names the route and the session, and the value is in
      # neither it nor the event.
      assert log =~ "credential_reflected"
      assert log =~ "/reflect/header"
      assert log =~ ctx.session.meta.test_id
      refute log =~ "managed-secret"
      refute inspect(meta, limit: :infinity) =~ "managed-secret"
    end

    test "in a small body is refused before the head is forwarded", ctx do
      tls = tunnel(ctx, ctx.token)
      :ssl.send(tls, raw("/reflect/body"))
      response = read_until_tls_closed(tls)
      assert response =~ "HTTP/1.1 502 Bad Gateway"
      refute response =~ "you sent"
      refute response =~ "managed-secret"
      assert_receive {:request, _, %{error: :credential_reflected}}
    end

    test "split across two chunks of a stream is caught with neither half forwarded", ctx do
      tls = tunnel(ctx, ctx.token)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          :ssl.send(tls, raw("/reflect/split"))
          response = read_until_tls_closed(tls)

          # The stream had started, so there is no status left to send: it
          # is cut. What came before the value arrived; no part of it did.
          assert response =~ "HTTP/1.1 200"
          assert response =~ "data: before"
          refute response =~ "502"
          refute response =~ "managed"
          refute response =~ "secret"
        end)

      assert_receive {:request, _, %{status: 200, error: :credential_reflected} = meta}
      # (The rule is named "managed", so it is the rest of the value that
      # has to be absent.)
      refute log =~ "managed-"
      refute log =~ "secret"
      refute inspect(meta, limit: :infinity) =~ "secret"
    end

    test "is not looked for under a coding that would hide it: the response is refused", ctx do
      tls = tunnel(ctx, ctx.token)

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          :ssl.send(tls, raw("/reflect/gzip", "Accept-Encoding: gzip\r\n"))
          response = read_until_tls_closed(tls)
          assert response =~ "HTTP/1.1 502 Bad Gateway"
          refute response =~ "content-encoding"
        end)

      assert log =~ "protected_response_encoded"
      assert_receive {:request, _, %{status: 502, error: :protected_response_encoded}}
    end

    test "a long stream without it arrives byte for byte, and the tunnel lives on", ctx do
      tls = tunnel(ctx, ctx.token)
      :ssl.send(tls, raw("/sse"))
      response = recv_until(tls, "\r\n0\r\n\r\n")
      [head, body] = String.split(response, "\r\n\r\n", parts: 2)
      assert head =~ "HTTP/1.1 200"

      expected =
        sse_chunks()
        |> Enum.map(&[Integer.to_string(byte_size(&1), 16), "\r\n", &1, "\r\n"])
        |> IO.iodata_to_binary()

      assert String.downcase(body) == String.downcase(expected <> "0\r\n\r\n")
      assert_receive {:request, _, %{status: 200, error: nil}}

      request(tls, raw("/report"))
      assert_receive {:origin_saw, %{path: "/report"}}
    end

    test "what was held back is delivered when the origin's close ends the body", ctx do
      # Bandit always frames a body, so this origin is a bare TLS socket: a
      # head with no length, a body ending on the bearer's first bytes, and
      # the close that ends it.
      {:ok, listener} =
        :ssl.listen(0, [:binary, active: false, reuseaddr: true] ++ ctx.origin_tls)

      {:ok, {_, port}} = :ssl.sockname(listener)

      origin =
        Task.async(fn ->
          {:ok, socket} = :ssl.transport_accept(listener, 5_000)
          {:ok, socket} = :ssl.handshake(socket, 5_000)
          {:ok, _request} = :ssl.recv(socket, 0, 5_000)

          :ok =
            :ssl.send(socket, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nends on manage")

          :ssl.close(socket)
        end)

      Memory.put(ctx.store, ctx.token, %{ctx.session | protected: %{ctx.policy | port: port}})
      tls = tunnel(ctx, ctx.token, "localhost:#{port}")
      :ssl.send(tls, raw("/allowed"))
      response = read_until_tls_closed(tls)
      Task.await(origin)
      :ssl.close(listener)

      assert response =~ "HTTP/1.1 200 OK"
      assert String.ends_with?(response, "\r\n\r\nends on manage")
      assert_receive {:request, _, %{status: 200, error: nil}}
    end

    test "an ordinary rule's response is not searched, in the same session", ctx do
      rule = %Rule{name: "plain", pattern: "127.0.0.1", scheme: :bearer, credential: "ordinary"}
      Agent.update(ctx.state, &%{&1 | rules: [rule]})
      Memory.put(ctx.store, ctx.token, %{ctx.session | rules: [rule]})

      tls = address_tunnel(ctx)

      # The origin echoes the credential straight back, and that is allowed.
      {head, body} = request(tls, "GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
      assert head =~ "200"
      assert body["headers"]["authorization"] == "Bearer ordinary"
      assert_receive {:request, _, %{status: 200, error: nil, scheme: :bearer}}

      # Its Accept-Encoding is its own, and so is the coding that comes back.
      :ssl.send(tls, "GET /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip\r\n\r\n")
      assert recv_until(tls, "\r\n\r\n") =~ "content-encoding: gzip"
      assert_receive {:request, _, %{status: 200, error: nil, scheme: :bearer}}
    end
  end

  # A tunnel to the same origin by address, which the protected rule (pinned
  # to `localhost`) does not cover. The leaf for an address is checked as an
  # address, so no name is sent.
  defp address_tunnel(ctx) do
    {tcp, reply} = connect(ctx, "127.0.0.1:#{ctx.https_port}", proxy_auth(ctx.token))
    assert reply =~ "HTTP/1.1 200"

    {:ok, tls} =
      :ssl.connect(
        tcp,
        [
          verify: :verify_peer,
          cacerts: [ctx.ca_der],
          server_name_indication: :disable,
          active: false
        ],
        5_000
      )

    tls
  end

  defp read_until_tls_closed(tls, acc \\ "") do
    case :ssl.recv(tls, 0, 5_000) do
      {:ok, data} -> read_until_tls_closed(tls, acc <> data)
      {:error, :closed} -> acc
    end
  end

  defp failure(:unavailable), do: {:error, "secret-in-error"}

  defp failure(:wrong_identity),
    do: {:ok, %ProtectedCredential{bearer: "secret-in-error", identity: "other"}}

  defp failure(:ordinary_rules),
    do: {:ok, [%Rule{pattern: "localhost", scheme: :bearer, credential: "secret-in-error"}]}

  defp failure(kind), do: {kind, "secret-in-error"}

  defp assert_refused(tls, path, status) do
    :ssl.send(tls, raw(path))
    assert recv_until(tls, "\r\n\r\n") =~ "HTTP/1.1 #{status}"
    assert {:error, :closed} = :ssl.recv(tls, 0, 2_000)
  end

  defp raw(path, headers \\ ""),
    do: "GET #{path} HTTP/1.1\r\nHost: localhost\r\nX-Report-To: #{@observer}\r\n#{headers}\r\n"

  defp post(path),
    do:
      "POST #{path} HTTP/1.1\r\nHost: localhost\r\nX-Report-To: #{@observer}\r\nContent-Length: 0\r\n\r\n"

  defp plain(ctx, host, port),
    do:
      "GET http://#{host}:#{port}/allowed HTTP/1.1\r\nHost: #{host}\r\nProxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
end
