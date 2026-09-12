defmodule Managoat.Broker.RequestAuthorizationTest do
  use Managoat.Broker.ProxyCase, async: true

  import ExUnit.CaptureLog

  alias Managoat.Broker.Store

  defmodule AuthorizingStore do
    @behaviour Store

    @impl Store
    def lookup(store, token), do: Memory.lookup(store, token)

    @impl Store
    def authorize(_store, authorization, request), do: authorize(authorization, request)

    @impl Store
    def authorize({state, pinned_generation}, request) do
      %{owner: owner, generation: generation, result: result} = Agent.get(state, & &1)
      send(owner, {:admission, self(), pinned_generation, request})

      if generation == pinned_generation do
        respond(result)
      else
        {:error, :denied}
      end
    end

    defp respond({:raise, secret}), do: raise(secret)
    defp respond({:exit, secret}), do: exit(secret)
    defp respond({:throw, secret}), do: throw(secret)

    defp respond({:pause, owner, rules}) do
      send(owner, {:admitted, self()})

      receive do
        :continue -> {:ok, rules}
      end
    end

    defp respond(result), do: result
  end

  setup do
    ctx = start_rig(store_module: AuthorizingStore)
    owner = self()
    fresh = bearer_session("fresh-token")

    state =
      start_supervised!(
        {Agent, fn -> %{owner: owner, generation: 1, result: {:ok, fresh.rules}} end}
      )

    session =
      bearer_session("cached-token", %{test_owner: owner}) |> Map.put(:authorization, {state, 1})

    token = put_session(ctx, session)
    session = attach_request_telemetry(Map.merge(ctx, %{session: session, token: token}))
    Map.merge(ctx, %{state: state, session: session, token: token, fresh: fresh})
  end

  test "every request in an existing tunnel uses a fresh admission and bearer", ctx do
    tls = tunnel(ctx, ctx.token)
    on_exit(fn -> :ssl.close(tls) end)
    refute_received {:admission, _, _, _}

    {head, body} = request(tls, "GET /first?q=1 HTTP/1.1\r\nHost: different.example\r\n\r\n")
    assert head =~ "200"
    assert body["headers"]["authorization"] == "Bearer fresh-token"

    assert_receive {:admission, _, 1,
                    %{
                      scheme: :https,
                      host: "localhost",
                      port: port,
                      method: "GET",
                      target: "/first?q=1"
                    }}

    assert port == ctx.https_port

    rotate(ctx, "rotated-token")
    {_, body} = request(tls, "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert body["headers"]["authorization"] == "Bearer rotated-token"
    assert_receive {:admission, _, 1, %{target: "/second"}}

    Agent.update(ctx.state, &%{&1 | generation: 2})
    assert_denied(tls, "/after-replacement", 403)
    assert_receive {:request, _, %{status: 403, error: :authorization_denied}}
  end

  for failure <- [:denied, :unavailable, :malformed, :raise, :exit, :throw] do
    test "#{failure} refuses a previously used tunnel without exposing the callback result",
         ctx do
      tls = tunnel(ctx, ctx.token)
      on_exit(fn -> :ssl.close(tls) end)
      request(tls, "GET /before HTTP/1.1\r\nHost: localhost\r\n\r\n")
      secret = "callback-secret-should-not-escape"
      failure = unquote(failure)

      result = failure_result(failure, secret)

      Agent.update(ctx.state, &%{&1 | result: result})
      status = failure_status(failure)
      log = capture_log(fn -> assert_denied(tls, "/after", status) end)
      refute log =~ secret
      assert_receive {:request, _, %{status: ^status, error: error} = meta}
      assert error in [:authorization_denied, :authorization_unavailable]
      refute inspect(meta) =~ secret
      refute Map.has_key?(meta, :authorization)
    end
  end

  test "a request admitted before revocation may finish; the next request is denied", ctx do
    tls = tunnel(ctx, ctx.token)
    on_exit(fn -> :ssl.close(tls) end)
    owner = self()
    Agent.update(ctx.state, &%{&1 | result: {:pause, owner, ctx.fresh.rules}})
    :ok = :ssl.send(tls, "GET /in-flight HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert_receive {:admitted, handler}, 2_000
    Agent.update(ctx.state, &%{&1 | generation: 2})
    send(handler, :continue)
    {_, body} = read_response(tls, "")
    assert body["headers"]["authorization"] == "Bearer fresh-token"
    assert_denied(tls, "/after-fence", 403)
  end

  test "streaming does not hold authorization work through the response", ctx do
    tls = tunnel(ctx, ctx.token)
    on_exit(fn -> :ssl.close(tls) end)
    name = "authorized_stream_#{System.unique_integer([:positive])}"

    :ok =
      :ssl.send(tls, "GET /stream HTTP/1.1\r\nHost: localhost\r\nX-Stream-Name: #{name}\r\n\r\n")

    assert recv_until(tls, "data: first") =~ "200"
    assert_receive {:admission, _, 1, %{target: "/stream"}}
    Agent.update(ctx.state, &%{&1 | generation: 2})
    send(String.to_existing_atom(name), :continue)
    assert recv_until(tls, "0\r\n\r\n") =~ "data: second"
    assert_denied(tls, "/after-stream", 403)
  end

  test "absolute-form requests are independently authorized against their actual destination",
       ctx do
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    on_exit(fn -> :gen_tcp.close(tcp) end)

    for credential <- ["one", "two"] do
      rotate(ctx, credential)
      :ok = :gen_tcp.send(tcp, plain_request(ctx, "/#{credential}"))
      {head, body} = read_plain_json(tcp)
      assert head =~ "200"
      assert body["headers"]["authorization"] == "Bearer #{credential}"
      assert_receive {:admission, _, 1, %{scheme: :http, host: "localhost", port: port}}
      assert port == ctx.http_port
    end

    Agent.update(ctx.state, &%{&1 | generation: 2})
    :ok = :gen_tcp.send(tcp, plain_request(ctx, "/denied"))
    assert read_until_closed(tcp) =~ "403 Forbidden"
  end

  test "a store without the callback cannot use cached opted-in credentials" do
    ctx = start_rig()
    session = bearer_session("must-not-forward") |> Map.put(:authorization, "grant-generation")
    token = put_session(ctx, session)
    tls = tunnel(ctx, token)
    assert_denied(tls, "/echo", 503)
  end

  test "callback dispatch preserves the pin and supports bare modules", ctx do
    request = %{scheme: :https, host: "localhost", port: 443, method: "GET", target: "/"}
    assert {:ok, resolved} = Store.authorize(AuthorizingStore, ctx.session, request)
    assert resolved.rules == ctx.fresh.rules
    assert resolved.authorization == ctx.session.authorization
    assert resolved.meta == ctx.session.meta
    assert resolved.unmatched_host_policy == ctx.session.unmatched_host_policy
    assert resolved.expires_at == ctx.session.expires_at
    assert ctx.session.rules != resolved.rules

    expired = %{ctx.session | expires_at: DateTime.add(DateTime.utc_now(), -1)}
    assert {:error, :authorization_denied} = Store.authorize(AuthorizingStore, expired, request)
  end

  test "fresh rules replace cached rules without weakening the pinned deny policy", ctx do
    session = %{ctx.session | unmatched_host_policy: :deny}
    Memory.put(ctx.store, ctx.token, session)
    tls = tunnel(ctx, ctx.token)
    rules = [%Rule{pattern: "localhost/allowed", scheme: :bearer, credential: "scoped"}]
    Agent.update(ctx.state, &%{&1 | result: {:ok, rules}})
    {_, body} = request(tls, "GET /allowed HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert body["headers"]["authorization"] == "Bearer scoped"
    assert_denied(tls, "/cached-rule-would-allow", 403)
  end

  test "unavailable authority also closes plain HTTP without using cached rules", ctx do
    Agent.update(ctx.state, &%{&1 | result: {:error, :unavailable}})
    {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])
    :ok = :gen_tcp.send(tcp, plain_request(ctx, "/unavailable"))
    assert read_until_closed(tcp) =~ "503 Service Unavailable"
    assert_receive {:request, _, %{status: 503, error: :authorization_unavailable}}
  end

  test "legacy sessions require no callback", ctx do
    legacy = bearer_session("legacy")
    assert {:ok, ^legacy} = Store.authorize(Memory, legacy, %{})
    token = put_session(ctx, legacy)
    tls = tunnel(ctx, token)
    on_exit(fn -> :ssl.close(tls) end)
    {_, body} = request(tls, "GET /legacy HTTP/1.1\r\nHost: localhost\r\n\r\n")
    assert body["headers"]["authorization"] == "Bearer legacy"
    refute_received {:admission, _, _, _}
  end

  defp failure_status(:denied), do: 403
  defp failure_status(_failure), do: 503

  defp failure_result(:denied, _secret), do: {:error, :denied}
  defp failure_result(:unavailable, _secret), do: {:error, :unavailable}
  defp failure_result(:malformed, secret), do: {:ok, [secret]}
  defp failure_result(failure, secret), do: {failure, secret}

  defp rotate(ctx, credential) do
    rules = bearer_session(credential).rules
    Agent.update(ctx.state, &%{&1 | result: {:ok, rules}})
  end

  defp assert_denied(tls, target, status) do
    :ok = :ssl.send(tls, "GET #{target} HTTP/1.1\r\nHost: localhost\r\n\r\n")
    response = recv_until(tls, "\r\n\r\n")
    assert response =~ "HTTP/1.1 #{status}"
    refute response =~ "token"
    assert {:error, :closed} = :ssl.recv(tls, 0, 2_000)
  end

  defp plain_request(ctx, target) do
    "GET http://localhost:#{ctx.http_port}#{target} HTTP/1.1\r\nHost: unrelated.example\r\nProxy-Authorization: #{proxy_auth(ctx.token)}\r\n\r\n"
  end
end
