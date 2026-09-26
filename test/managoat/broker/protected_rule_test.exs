defmodule Managoat.Broker.ProtectedRuleTest do
  use ExUnit.Case, async: true
  alias Managoat.Broker.{ProtectedCredential, ProtectedRule, Rule, Session, Store}

  defp policy do
    %ProtectedRule{
      host: "provider.example",
      port: 443,
      paths: ["/responses", "/api/"],
      methods: ["GET", "POST"],
      identity: "acct-1",
      identity_header: "x-account-id",
      allowed_headers: ["content-type"]
    }
  end

  defp session(policy), do: %Session{protected: policy, http_only: true, authorization: :pinned}

  defp request(target),
    do: %{scheme: :https, host: "provider.example", port: 443, method: "POST", target: target}

  test "server policy validation rejects unsafe persisted configuration" do
    policy = policy()
    assert ProtectedRule.valid_session?(session(policy))
    assert ProtectedRule.destination?(session(policy), "PROVIDER.EXAMPLE", 443)
    refute ProtectedRule.destination?(session(policy), "another.example", 443)
    assert ProtectedRule.valid_session?(%Session{})
    refute ProtectedRule.valid_session?(%{session(policy) | authorization: nil})
    refute ProtectedRule.valid_session?(%{session(policy) | http_only: false})

    refute ProtectedRule.valid_session?(%{
             session(policy)
             | protected: %{host: "provider.example"}
           })

    for change <- [
          host: "*.example",
          host: "Provider.Example",
          host: nil,
          port: 0,
          paths: [],
          methods: [],
          methods: ["TRACE"],
          paths: [1],
          paths: ["/../other"],
          paths: ["/x%2fy"],
          identity: "",
          identity: "bad\nidentity",
          identity_header: "authorization",
          identity_header: "x bad",
          allowed_headers: ["host"],
          allowed_headers: ["x-forwarded-host"],
          allowed_headers: ["cookie"],
          name: 12,
          query: :forward,
          query: nil
        ] do
      refute ProtectedRule.valid_session?(session(struct!(policy, [change]))), inspect(change)
    end
  end

  test "exact paths and explicit subtrees do not widen to adjacent routes" do
    policy = policy()

    for target <- ["/responses", "/api/", "/api/nested/route"] do
      assert {:ok, ^policy} = ProtectedRule.select(session(policy), request(target))
    end

    for target <- [
          "/responses/extra",
          "/responses-else",
          "/api",
          "/api/../outside",
          "/api//x",
          "/api/%2e%2e/x",
          "/api/\\outside",
          "/api/x#fragment",
          "https://provider.example/api/x"
        ] do
      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), request(target))
    end

    assert {:error, :protected_destination} =
             ProtectedRule.select(session(policy), %{request("/responses") | method: "HEAD"})

    assert :ordinary = ProtectedRule.select(%Session{}, request("/responses"))

    assert :ordinary =
             ProtectedRule.select(session(policy), %{request("/") | host: "other.example"})

    assert {:error, :protected_destination} =
             ProtectedRule.select(session(policy), %{request("/responses") | scheme: :http})

    assert {:error, :protected_destination} =
             ProtectedRule.select(session(policy), %{request("/responses") | port: 8443})
  end

  test "a query on a protected route is refused unless the policy allows one" do
    policy = policy()
    assert policy.query == :refuse

    for target <- ["/responses?model=test", "/responses?", "/api/nested?x=1", "/responses??"] do
      assert {:error, :protected_query} = ProtectedRule.select(session(policy), request(target))
    end

    allowing = %{policy | query: :allow}
    assert ProtectedRule.valid_session?(session(allowing))

    for target <- ["/responses", "/responses?model=test", "/responses?"] do
      assert {:ok, ^allowing} = ProtectedRule.select(session(allowing), request(target))
    end

    # The path is judged first, so a wrong route says so whatever follows it.
    for policy <- [policy, allowing], target <- ["/other?x=1", "/responses#frag?x=1"] do
      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), request(target))
    end

    # A policy persisted before the key existed reads as the default.
    legacy = Map.delete(policy, :query)
    assert ProtectedRule.valid_session?(session(legacy))
    assert {:ok, _} = ProtectedRule.select(session(legacy), request("/responses"))

    assert {:error, :protected_query} =
             ProtectedRule.select(session(legacy), request("/responses?x=1"))
  end

  describe "routes" do
    defp routed do
      %ProtectedRule{
        host: "provider.example",
        port: 443,
        identity: "acct-1",
        identity_header: "x-account-id",
        allowed_headers: ["content-type"],
        routes: [
          %{path: "/codex/responses", methods: ["POST"], query: :refuse},
          %{path: "/codex/models", methods: ["GET"], query: {:only, ["client_version"]}}
        ]
      }
    end

    defp get(target), do: %{request(target) | method: "GET"}

    test "each route admits its own method and query and nothing of the other's" do
      policy = routed()
      assert ProtectedRule.valid_session?(session(policy))

      assert {:ok, ^policy} = ProtectedRule.select(session(policy), request("/codex/responses"))

      for target <- ["/codex/models", "/codex/models?client_version=0.44.0"] do
        assert {:ok, ^policy} = ProtectedRule.select(session(policy), get(target))
      end

      # The other route's method is not this route's.
      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), request("/codex/models"))

      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), get("/codex/responses"))

      # Nor is the other route's query policy.
      assert {:error, :protected_query} =
               ProtectedRule.select(
                 session(policy),
                 request("/codex/responses?client_version=1")
               )

      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), get("/codex/models/extra"))
    end

    test "a pinned query admits only its names, once each, spelled plainly" do
      policy = routed()

      for query <- [
            "client_version=0.44.0",
            "client_version=",
            "client_version=a%2Fb+c",
            "client_version=1.2.3-alpha+build:x@y!$'()*,/"
          ] do
        assert {:ok, _} = ProtectedRule.select(session(policy), get("/codex/models?" <> query)),
               query
      end

      for query <- [
            # Unpinned, extra, or repeated names.
            "model=x",
            "client_version=1&model=x",
            "model=x&client_version=1",
            "client_version=1&client_version=2",
            # Another spelling of the pinned name.
            "Client_Version=1",
            "client%5Fversion=1",
            "client_version%3D=1",
            "client+version=1",
            " client_version=1",
            # Malformed: empty, empty pair, no `=`, a second `=`.
            "",
            "&client_version=1",
            "client_version=1&",
            "client_version",
            "client_version=1=2",
            # Separators and characters an origin may read differently.
            "client_version=1;model=x",
            "client_version=1?model=x",
            "client_version=1#frag",
            "client_version=%",
            "client_version=%zz",
            "client_version=%4",
            # Values that decode to control characters.
            "client_version=%00",
            "client_version=a%0d%0aX-Injected:%201",
            "client_version=%7F"
          ] do
        assert {:error, :protected_query} =
                 ProtectedRule.select(session(policy), get("/codex/models?" <> query)),
               inspect(query)
      end
    end

    test "overlapping routes are a union, and a route without a query key refuses one" do
      policy = %{
        routed()
        | routes: [
            %{path: "/api/", methods: ["GET"]},
            %{path: "/api/search", methods: ["GET"], query: :allow}
          ]
      }

      assert ProtectedRule.valid_session?(session(policy))
      assert {:ok, _} = ProtectedRule.select(session(policy), get("/api/search?q=anything"))
      assert {:ok, _} = ProtectedRule.select(session(policy), get("/api/other"))

      assert {:error, :protected_query} =
               ProtectedRule.select(session(policy), get("/api/other?q=1"))
    end

    test "scheme, port and host still gate every route" do
      policy = routed()
      target = "/codex/models?client_version=1"

      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), %{get(target) | scheme: :http})

      assert {:error, :protected_destination} =
               ProtectedRule.select(session(policy), %{get(target) | port: 8443})

      assert :ordinary =
               ProtectedRule.select(session(policy), %{get(target) | host: "other.example"})
    end

    test "malformed routes, and a policy written both ways, are invalid" do
      policy = routed()
      [responses, models] = policy.routes

      for routes <- [
            [],
            :all,
            [%{}],
            [%{path: "/codex/models"}],
            [%{methods: ["GET"]}],
            [%{responses | path: "codex"}],
            [%{responses | path: "/codex/../x"}],
            [%{responses | path: "/x%2fy"}],
            [%{responses | path: "/x?y"}],
            [%{responses | methods: []}],
            [%{responses | methods: ["TRACE"]}],
            [%{responses | methods: ["CONNECT"]}],
            [%{responses | methods: "POST"}],
            [%{responses | query: nil}],
            [%{responses | query: :forward}],
            [%{models | query: {:only, []}}],
            [%{models | query: {:only, "client_version"}}],
            [%{models | query: {:only, ["client_version", "client_version"]}}],
            [%{models | query: {:only, ["client version"]}}],
            [%{models | query: {:only, ["a%62"]}}],
            [%{models | query: {:only, ["a=b"]}}],
            [%{models | query: {:only, ["a&b"]}}],
            [%{models | query: {:only, [:client_version]}}],
            [%{models | query: {:only, [""]}}],
            [%{models | query: {:except, ["x"]}}],
            [Map.put(responses, :method, "GET")],
            [{"/codex/responses", ["POST"]}],
            [responses, nil]
          ] do
        refute ProtectedRule.valid_session?(session(%{policy | routes: routes})), inspect(routes)
      end

      # `routes` replaces the joint fields; setting both is refused rather
      # than resolved in favour of either.
      for change <- [
            paths: ["/codex/responses"],
            methods: ["GET"],
            query: :allow
          ] do
        refute ProtectedRule.valid_session?(session(struct!(policy, [change]))), inspect(change)
      end

      assert ProtectedRule.valid_session?(session(%{policy | paths: [], methods: []}))

      # `{:only, _}` belongs to a route; the joint `query` does not take it.
      refute ProtectedRule.valid_session?(
               session(%{policy() | query: {:only, ["client_version"]}})
             )

      # And without routes, the joint fields are still required.
      refute ProtectedRule.valid_session?(session(%{policy() | paths: nil}))
      refute ProtectedRule.valid_session?(session(%{policy() | methods: nil}))
    end

    test "a policy persisted before routes existed reads as one without them" do
      legacy = policy() |> Map.delete(:routes) |> Map.delete(:query)
      assert ProtectedRule.valid_session?(session(legacy))
      assert {:ok, _} = ProtectedRule.select(session(legacy), request("/responses"))
      assert {:ok, _} = ProtectedRule.select(session(legacy), get("/api/x"))

      assert {:error, :protected_query} =
               ProtectedRule.select(session(legacy), request("/responses?client_version=1"))

      assert {:error, :protected_destination} =
               ProtectedRule.select(session(legacy), %{request("/responses") | method: "PUT"})
    end

    test "an ordinary injection rule overlapping any route conflicts" do
      policy = routed()
      ordinary = %Rule{pattern: "provider.example/codex/models", scheme: :bearer, credential: "x"}
      session = %{session(policy) | rules: [ordinary]}

      assert {:error, :protected_conflict} =
               ProtectedRule.prepare(policy, session, get("/codex/models?client_version=1"), [])

      # The rule's path does not reach the other route.
      assert {:ok, _} = ProtectedRule.prepare(policy, session, request("/codex/responses"), [])

      host_wide = %{ordinary | pattern: "provider.example"}

      for req <- [request("/codex/responses"), get("/codex/models?client_version=1")] do
        assert {:error, :protected_conflict} =
                 ProtectedRule.prepare(policy, %{session | rules: [host_wide]}, req, [])
      end
    end
  end

  test "an allowlisted Accept-Encoding is still replaced with identity" do
    policy = %{policy() | allowed_headers: ["accept-encoding"]}

    assert {:ok, [{"host", "provider.example"}, {"accept-encoding", "identity"}]} =
             ProtectedRule.prepare(policy, session(policy), request("/responses"), [
               {"accept-encoding", "gzip"},
               {"Accept-Encoding", "zstd"}
             ])
  end

  test "only safe headers, the pinned identity and a fresh bearer are emitted" do
    policy = %{policy() | allowed_headers: ["content-type", "x-account-id"]}

    raw = [
      {"Host", "attacker.example"},
      {"Authorization", "fake"},
      {"X-Account-ID", "other"},
      {"Content-Type", "application/json"},
      {"Content-Length", "2"},
      {"Accept-Encoding", "gzip, br"},
      {"X-Unknown", "drop"}
    ]

    assert {:ok, headers} =
             ProtectedRule.prepare(policy, session(policy), request("/responses"), raw)

    credential = %ProtectedCredential{bearer: "fresh-token", identity: "acct-1"}

    assert {:ok, headers, "/responses?x=1", ^policy} =
             ProtectedRule.inject(policy, credential, headers, "/responses?x=1")

    assert headers == [
             {"authorization", "Bearer fresh-token"},
             {"x-account-id", "acct-1"},
             {"host", "provider.example"},
             {"accept-encoding", "identity"},
             {"Content-Type", "application/json"},
             {"Content-Length", "2"}
           ]

    refute inspect(credential) =~ "fresh-token"
    refute inspect(credential) =~ "acct-1"
    assert_raise Protocol.UndefinedError, fn -> Jason.encode!(credential) end
  end

  test "mismatched identity and unusable bearer values cannot be served" do
    for credential <- [
          %ProtectedCredential{bearer: "fresh", identity: "different"},
          %ProtectedCredential{bearer: nil, identity: "acct-1"},
          %ProtectedCredential{bearer: "", identity: "acct-1"},
          %ProtectedCredential{bearer: "token\r\nUpgrade: ws", identity: "acct-1"}
        ] do
      assert {:error, :authorization_unavailable} =
               ProtectedRule.inject(policy(), credential, [], "/responses")
    end
  end

  test "ordinary overlapping injection conflicts while unrelated and passthrough rules do not" do
    policy = policy()
    ordinary = %Rule{pattern: "provider.example", scheme: :custom, credential: %{}, template: %{}}

    assert {:error, :protected_conflict} =
             ProtectedRule.prepare(
               policy,
               %{session(policy) | rules: [ordinary]},
               request("/responses"),
               []
             )

    for rule <- [%{ordinary | pattern: "other.example"}, %{ordinary | scheme: :passthrough}] do
      assert {:ok, _} =
               ProtectedRule.prepare(
                 policy,
                 %{session(policy) | rules: [rule]},
                 request("/responses"),
                 []
               )
    end

    assert {:error, :unsafe_request} =
             ProtectedRule.prepare(policy, session(policy), request("/responses"), [
               {"Transfer-Encoding", "chunked"}
             ])
  end

  test "IPv6 authority and nonstandard pinned port are serialized without ambiguity" do
    policy = %{policy() | host: "::1", port: 8443}
    assert ProtectedRule.valid_session?(session(policy))
    assert ProtectedRule.destination?(session(policy), "::1", 8443)
    refute ProtectedRule.destination?(session(policy), "::1", 443)

    assert {:ok, [{"host", "[::1]:8443"}, {"accept-encoding", "identity"}]} =
             ProtectedRule.prepare(
               policy,
               session(policy),
               %{request("/responses") | host: "::1", port: 8443},
               []
             )
  end

  test "missing callbacks and expired authority fail closed" do
    assert {:error, :authorization_unavailable} =
             Store.authorize_protected(__MODULE__, session(policy()), request("/responses"))

    expired = %{session(policy()) | expires_at: DateTime.add(DateTime.utc_now(), -1)}

    assert {:error, :authorization_denied} =
             Store.authorize_protected(__MODULE__, expired, request("/responses"))
  end
end
