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
          name: 12
        ] do
      refute ProtectedRule.valid_session?(session(struct!(policy, [change]))), inspect(change)
    end
  end

  test "exact paths and explicit subtrees do not widen to adjacent routes" do
    policy = policy()

    for target <- ["/responses", "/responses?model=test", "/api/", "/api/nested/route"] do
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

  test "only safe headers, the pinned identity and a fresh bearer are emitted" do
    policy = %{policy() | allowed_headers: ["content-type", "x-account-id"]}

    raw = [
      {"Host", "attacker.example"},
      {"Authorization", "fake"},
      {"X-Account-ID", "other"},
      {"Content-Type", "application/json"},
      {"Content-Length", "2"},
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

    assert {:ok, [{"host", "[::1]:8443"}]} =
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
