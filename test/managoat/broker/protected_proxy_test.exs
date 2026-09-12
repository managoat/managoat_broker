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

  setup do
    ctx = start_rig(store_module: ProtectedStore)

    policy = %ProtectedRule{
      host: "localhost",
      port: ctx.https_port,
      paths: ["/allowed", "/stream"],
      methods: ["GET", "POST"],
      identity: "account-1",
      identity_header: "x-account-id",
      allowed_headers: ["content-type", "x-stream-name"],
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

    {_, body} =
      request(
        tls,
        "GET /allowed HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: fake\r\nX-Account-ID: another\r\nCookie: identity=another\r\nX-Forwarded-Host: attacker.example\r\nContent-Type: application/json\r\n\r\n"
      )

    assert body["headers"]["authorization"] == "Bearer managed-secret"
    assert body["headers"]["x-account-id"] == "account-1"
    assert body["headers"]["host"] == "localhost:#{ctx.https_port}"
    assert body["headers"]["content-type"] == "application/json"
    refute Map.has_key?(body["headers"], "cookie")
    refute Map.has_key?(body["headers"], "x-forwarded-host")
    assert_receive {:authorize, %{protected: true, target: "/allowed"}}
    assert_receive {:request, _, %{scheme: :protected_bearer}}
  end

  test "rotation and revocation affect requests inside the same tunnel", ctx do
    tls = tunnel(ctx, ctx.token)
    request(tls, raw("/allowed"))

    Agent.update(
      ctx.state,
      &%{&1 | result: {:ok, %ProtectedCredential{bearer: "rotated", identity: "account-1"}}}
    )

    {_, body} = request(tls, raw("/allowed"))
    assert body["headers"]["authorization"] == "Bearer rotated"
    Agent.update(ctx.state, &%{&1 | generation: 2})
    assert_refused(tls, "/allowed", 403)
  end

  for failure <- [:unavailable, :raise, :exit, :throw, :wrong_identity, :ordinary_rules] do
    test "#{failure} never falls back to cached credentials", ctx do
      tls = tunnel(ctx, ctx.token)
      request(tls, raw("/allowed"))
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
      paths: ["/allowed"],
      methods: ["GET", "POST"],
      identity: "id",
      identity_header: "x-id",
      allowed_headers: []
    }

    token =
      put_session(ctx, %Session{protected: policy, http_only: true, authorization: {state, 1}})

    tls = tunnel(ctx, token)
    {_, body} = request(tls, raw("/allowed"))
    assert body["headers"]["authorization"] == "Bearer verified"
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

  defp raw(path, headers \\ ""), do: "GET #{path} HTTP/1.1\r\nHost: localhost\r\n#{headers}\r\n"

  defp plain(ctx, host, port),
    do:
      "GET http://#{host}:#{port}/allowed HTTP/1.1\r\nHost: #{host}\r\nProxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
end
