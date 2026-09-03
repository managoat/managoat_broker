defmodule Managoat.Broker.InjectorTest do
  use ExUnit.Case, async: true

  alias Managoat.Broker.{Injector, Rule, Session}

  @session %Session{
    rules: [
      %Rule{
        name: "github-api",
        pattern: "api.github.com",
        scheme: :bearer,
        credential: "ghp_real"
      },
      %Rule{
        name: "github-git",
        pattern: "github.com",
        scheme: :basic,
        credential: {"x-access-token", "ghp_real"}
      },
      %Rule{
        name: "anthropic",
        pattern: "api.anthropic.com",
        scheme: :api_key,
        header: "x-api-key",
        credential: "sk-ant-real"
      },
      %Rule{
        name: "discord",
        pattern: "discord.com/api/*",
        scheme: :api_key,
        prefix: "Bot ",
        credential: "disc"
      },
      %Rule{
        name: "pagerduty",
        pattern: "api.pagerduty.com",
        scheme: :custom,
        template: %{
          "Authorization" => "Token token={{ PAGERDUTY_TOKEN }}",
          "X-Missing" => "{{ NOT_A_KEY }}"
        },
        credential: %{"PAGERDUTY_TOKEN" => "pd"}
      },
      %Rule{
        name: "openai-sub",
        pattern: "api.openai.com",
        scheme: :substitute,
        placeholder: "sk-__openai_api_key__",
        credential: "sk-real-openai"
      },
      %Rule{
        name: "allowed",
        pattern: "registry.npmjs.org",
        scheme: :passthrough
      }
    ],
    unmatched_host_policy: :passthrough
  }

  @headers [
    {"Host", "api.github.com"},
    {"Proxy-Authorization", "Basic abc"},
    {"Authorization", "Bearer __github_token__"},
    {"Accept", "application/json"}
  ]

  # The tests below this are about headers, so they drop the forwarded
  # target; the target substitution has its own tests at the end, which
  # call `Injector.inject/5` directly.
  defp inject(headers, host, path \\ "/", session \\ @session) do
    case Injector.inject(headers, host, 443, path, session) do
      {:ok, headers, _target, rule} -> {:ok, headers, rule}
      other -> other
    end
  end

  test "a bearer rule replaces the authorization header wholesale" do
    assert {:ok, headers, "github-api"} = inject(@headers, "api.github.com")

    assert {"authorization", "Bearer ghp_real"} in headers
    refute Enum.any?(headers, fn {k, _} -> String.downcase(k) == "proxy-authorization" end)
    assert Enum.count(headers, fn {k, _} -> String.downcase(k) == "authorization" end) == 1
    assert {"Accept", "application/json"} in headers
  end

  test "a basic rule encodes username and password" do
    {:ok, headers, "github-git"} = inject(@headers, "github.com")
    assert {"authorization", "Basic " <> Base.encode64("x-access-token:ghp_real")} in headers
  end

  test "an api-key rule writes its own header, and leaves authorization alone" do
    headers = [{"x-api-key", "__anthropic_api_key__"}, {"Authorization", "Bearer keep"}]
    {:ok, out, "anthropic"} = inject(headers, "api.anthropic.com")

    assert {"x-api-key", "sk-ant-real"} in out
    assert {"Authorization", "Bearer keep"} in out
    refute {"x-api-key", "__anthropic_api_key__"} in out
  end

  test "an api-key rule with a prefix and no header writes Authorization with the prefix" do
    {:ok, out, "discord"} = inject(@headers, "discord.com", "/api/v10/users/@me")
    assert {"Authorization", "Bot disc"} in out
    refute {"Authorization", "Bearer __github_token__"} in out
  end

  test "a custom rule renders every {{ KEY }} it holds and leaves one it does not" do
    {:ok, out, "pagerduty"} = inject(@headers, "api.pagerduty.com")
    assert {"Authorization", "Token token=pd"} in out
    assert {"X-Missing", "{{ NOT_A_KEY }}"} in out
  end

  test "a substitute rule replaces the placeholder wherever a header value carries it" do
    headers = [
      {"Host", "api.openai.com"},
      {"Authorization", "Bearer sk-__openai_api_key__"},
      {"X-Also", "prefix sk-__openai_api_key__ suffix"},
      {"X-Other", "untouched"}
    ]

    {:ok, out, "openai-sub"} = inject(headers, "api.openai.com")
    assert {"Authorization", "Bearer sk-real-openai"} in out
    assert {"X-Also", "prefix sk-real-openai suffix"} in out
    assert {"X-Other", "untouched"} in out
  end

  test "a substitute rule with a valid placeholder and no credential forwards it as written" do
    # The same choice `:custom` makes for an unfilled `{{ KEY }}`: the
    # origin refuses a placeholder, which is a clearer failure than a
    # credential sent empty, and the proxy has nothing better to do.
    headers = [{"Authorization", "Bearer __api_token__"}]

    session = %Session{
      rules: [
        %Rule{
          name: "missing",
          pattern: "api.example.com",
          scheme: :substitute,
          placeholder: "__api_token__"
        }
      ]
    }

    assert {:ok, ^headers, "missing"} = inject(headers, "api.example.com", "/", session)
  end

  test "a substitute rule whose placeholder is not usable as one is refused" do
    # This used to pass through silently, which is the failure mode the
    # check exists for: a rule that cannot do its job doing nothing.
    for placeholder <- ["", "id", "token", "account_sid"] do
      session = %Session{
        rules: [
          %Rule{
            name: "bad",
            pattern: "api.example.com",
            scheme: :substitute,
            placeholder: placeholder,
            credential: "real"
          }
        ]
      }

      assert {:error, {:unusable_placeholder, "bad"}} =
               inject([{"Authorization", "x"}], "api.example.com", "/", session),
             "#{inspect(placeholder)} was accepted"
    end
  end

  describe "valid_placeholder?/1" do
    test "a placeholder needs length, a letter or digit, and a boundary" do
      for good <- ~w(__github_token__ sk-__openai_api_key__ {{TOKEN}} __a__ tok-en x.y.z __1__) do
        assert Injector.valid_placeholder?(good), "#{good} was rejected"
      end

      for bad <- ["", "id", "abc", "token", "account_sid", "APIKEY", "____", "___"] do
        refute Injector.valid_placeholder?(bad), "#{inspect(bad)} was accepted"
      end
    end

    test "anything that is not a binary is not a placeholder" do
      refute Injector.valid_placeholder?(nil)
      refute Injector.valid_placeholder?(:token)
    end
  end

  test "a substitute rule and a header rule on one host both apply; the first names the outcome" do
    session = %Session{
      rules: [
        %Rule{
          name: "sub",
          pattern: "api.anthropic.com",
          scheme: :substitute,
          placeholder: "__oauth__",
          credential: "oauth-real"
        },
        %Rule{
          name: "key",
          pattern: "api.anthropic.com",
          scheme: :api_key,
          header: "x-api-key",
          credential: "sk-real"
        }
      ]
    }

    headers = [{"Authorization", "Bearer __oauth__"}, {"x-api-key", "__key__"}]
    {:ok, out, "sub"} = inject(headers, "api.anthropic.com", "/v1/messages", session)
    assert {"Authorization", "Bearer oauth-real"} in out
    assert {"x-api-key", "sk-real"} in out
  end

  test "a passthrough rule forwards the request untouched but for the hop-by-hop headers" do
    {:ok, out, "allowed"} = inject(@headers, "registry.npmjs.org")
    assert {"Authorization", "Bearer __github_token__"} in out
    refute Enum.any?(out, fn {k, _} -> k == "Proxy-Authorization" end)
  end

  test "an unmatched host passes through with only the hop-by-hop headers dropped" do
    {:ok, headers, nil} = inject(@headers, "example.com")

    assert {"Authorization", "Bearer __github_token__"} in headers
    refute Enum.any?(headers, fn {k, _} -> k == "Proxy-Authorization" end)
  end

  test "deny refuses an unmatched host and lets a passthrough rule allow one" do
    session = %{@session | unmatched_host_policy: :deny}
    assert {:error, :denied} = inject(@headers, "example.com", "/", session)
    assert {:ok, _, "github-api"} = inject(@headers, "api.github.com", "/", session)
    assert {:ok, _, "allowed"} = inject(@headers, "registry.npmjs.org", "/", session)
  end

  test "the match is on the exact host: api.github.com is not github.com" do
    {:ok, _, "github-git"} = inject(@headers, "github.com")
    {:ok, _, nil} = inject(@headers, "gist.github.com")
  end

  describe "matches?/4" do
    test "host, case-insensitively, any port" do
      assert Injector.matches?("api.stripe.com", "API.Stripe.com", 443, "/v1")
      refute Injector.matches?("api.stripe.com", "stripe.com", 443, "/")
    end

    test "a wildcard host matches subdomains only" do
      assert Injector.matches?("*.atlassian.net", "acme.atlassian.net", 443, "/")
      refute Injector.matches?("*.atlassian.net", "atlassian.net", 443, "/")
    end

    test "a port pins the port" do
      assert Injector.matches?("db.example.com:8443", "db.example.com", 8443, "/")
      refute Injector.matches?("db.example.com:8443", "db.example.com", 443, "/")
    end

    test "a path is a prefix; a trailing * matches the rest; the query is ignored" do
      assert Injector.matches?("discord.com/api/*", "discord.com", 443, "/api/v10/x?y=1")
      refute Injector.matches?("discord.com/api/*", "discord.com", 443, "/oauth2")
      assert Injector.matches?("h.example/v1", "h.example", 443, "/v1")
      assert Injector.matches?("h.example/v1", "h.example", 443, "/v1/users")
      refute Injector.matches?("h.example/v1", "h.example", 443, "/v10")
    end
  end

  test "host_matches?/3 ignores the path part of the pattern" do
    assert Injector.host_matches?("discord.com/api/*", "discord.com", 443)
    refute Injector.host_matches?("discord.com:8443/api/*", "discord.com", 443)
    refute Injector.host_matches?("api.example.com", "example.com", 443)
  end

  describe "substitution into the request target" do
    # The canonical shape a header-only substitution could not broker: a bot
    # API with the token in the path. Agent Vault shipped a `telegram`
    # preset for exactly this.
    @bot %Session{
      rules: [
        %Rule{
          name: "telegram",
          pattern: "api.telegram.org",
          scheme: :substitute,
          placeholder: "__bot_token__",
          credential: "123456:AAE-real"
        }
      ],
      unmatched_host_policy: :passthrough,
      expires_at: ~U[2099-01-01 00:00:00Z]
    }

    defp target(t, session \\ @bot, host \\ "api.telegram.org") do
      Injector.inject([{"Accept", "*/*"}], host, 443, t, session)
    end

    test "a placeholder in the path is replaced in the forwarded target" do
      assert {:ok, _, "/bot123456:AAE-real/sendMessage", "telegram"} =
               target("/bot__bot_token__/sendMessage")
    end

    test "a placeholder in the query is replaced too" do
      assert {:ok, _, "/v1/models?key=123456:AAE-real&alt=sse", "telegram"} =
               target("/v1/models?key=__bot_token__&alt=sse")
    end

    test "a placeholder in the target and in a header are both replaced" do
      assert {:ok, headers, "/bot123456:AAE-real/x", "telegram"} =
               Injector.inject(
                 [{"X-Token", "__bot_token__"}],
                 "api.telegram.org",
                 443,
                 "/bot__bot_token__/x",
                 @bot
               )

      assert {"X-Token", "123456:AAE-real"} in headers
    end

    test "a target with no placeholder is forwarded unchanged" do
      assert {:ok, _, "/getMe", "telegram"} = target("/getMe")
    end

    test "an unmatched host forwards the target untouched" do
      assert {:ok, _, "/bot__bot_token__/x", nil} =
               target("/bot__bot_token__/x", @bot, "example.com")
    end

    test "several substitute rules apply to the target in rule order" do
      session = %{
        @bot
        | rules: [
            %Rule{
              name: "a",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__a__",
              credential: "AA"
            },
            %Rule{
              name: "b",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__b__",
              credential: "BB"
            }
          ]
      }

      assert {:ok, _, "/AA/BB", "a"} = target("/__a__/__b__", session, "h.test")
    end

    test "a chained placeholder is not re-substituted by a later rule" do
      # `a` writes a value that contains `b`'s placeholder. Rules apply in
      # order, so `b` does see it — this test pins that behaviour down
      # rather than leaving it to be discovered.
      session = %{
        @bot
        | rules: [
            %Rule{
              name: "a",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__a__",
              credential: "__b__"
            },
            %Rule{
              name: "b",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__b__",
              credential: "BB"
            }
          ]
      }

      assert {:ok, _, "/BB", "a"} = target("/__a__", session, "h.test")
    end

    test "matching still uses the original target, not the rewritten one" do
      # The rule's path prefix is the client's path. If matching ran on the
      # rewritten target the credential's own bytes could change the answer.
      session = %{
        @bot
        | rules: [
            %Rule{
              name: "scoped",
              pattern: "h.test/bot__bot_token__",
              scheme: :substitute,
              placeholder: "__bot_token__",
              credential: "SECRET"
            }
          ]
      }

      assert {:ok, _, "/botSECRET/x", "scoped"} =
               target("/bot__bot_token__/x", session, "h.test")
    end

    test "deny still refuses a path no rule matches, whatever the placeholder" do
      session = %{
        @bot
        | rules: [%Rule{name: "ok", pattern: "h.test/allowed", scheme: :passthrough}],
          unmatched_host_policy: :deny
      }

      assert {:error, :denied} = target("/bot__bot_token__/x", session, "h.test")
      assert {:ok, _, "/allowed/x", "ok"} = target("/allowed/x", session, "h.test")
    end

    test "reserved characters go into the target verbatim, unencoded" do
      # A Telegram bot token holds a `:`, which is legal unencoded in a path
      # segment; `%3A` would be a different URL. The proxy cannot know which
      # component a placeholder sits in, so it never encodes.
      session = %{
        @bot
        | rules: [
            %Rule{
              name: "r",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__p__",
              credential: "a:b/c?d&e=f+g%20h@i"
            }
          ]
      }

      assert {:ok, _, "/x/a:b/c?d&e=f+g%20h@i", "r"} = target("/x/__p__", session, "h.test")
    end

    test "a credential holding CR or LF is refused in a header too" do
      # A header value ends at CRLF, so a credential carrying one would
      # start a second header field the tenant never wrote.
      session = %{
        @bot
        | rules: [
            %Rule{
              name: "r",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__p__",
              credential: "tok\r\nX-Injected: yes"
            }
          ]
      }

      assert {:error, {:unsafe_credential, "r", :header}} =
               Injector.inject([{"Authorization", "__p__"}], "h.test", 443, "/x", session)
    end

    test "a credential that would split the request line is refused" do
      for bad <- ["a\r\nGET /evil HTTP/1.1", "a b", "a\tb", "a\u007fb"] do
        session = %{
          @bot
          | rules: [
              %Rule{
                name: "r",
                pattern: "h.test",
                scheme: :substitute,
                placeholder: "__p__",
                credential: bad
              }
            ]
        }

        assert {:error, {:unsafe_credential, "r", :target}} =
                 target("/x/__p__", session, "h.test")
      end
    end

    test "an unsafe credential is refused only when it reaches the target" do
      # A space is legal in a header value, so a substitution that never
      # touches the target must not be refused for one.
      session = %{
        @bot
        | rules: [
            %Rule{
              name: "r",
              pattern: "h.test",
              scheme: :substitute,
              placeholder: "__p__",
              credential: "Signature keyId=\"x\", sig=\"y\""
            }
          ]
      }

      assert {:ok, headers, "/x", "r"} =
               Injector.inject([{"Authorization", "__p__"}], "h.test", 443, "/x", session)

      assert {"Authorization", "Signature keyId=\"x\", sig=\"y\""} in headers
    end
  end
end
