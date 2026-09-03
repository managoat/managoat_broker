defmodule Managoat.Broker.IPv6Test do
  # IPv6 upstreams: the guard first, then resolution, then the grammar that
  # lets a literal be named at all.
  use Managoat.Broker.ProxyCase, async: true

  alias Managoat.Broker.{CA, HTTP, Injector, Proxy}

  describe "the SSRF guard" do
    @blocked ~w(
      :: ::1 fe80::1 febf::1 fec0::1 feff::1 fc00::1 fdff::1
      ff02::1 ff00::1 2001:db8::1 100::1
      ::ffff:169.254.169.254 ::ffff:10.0.0.1 ::ffff:127.0.0.1 ::ffff:192.168.1.1
      ::ffff:172.16.0.1 ::ffff:100.64.0.1 ::169.254.169.254
      2002:a9fe:a9fe:: 64:ff9b::169.254.169.254
    )

    @allowed ~w(
      2001:4860:4860::8888 2606:4700:4700::1111 2a00:1450:4001::200e
      2002:8c52:7003:: 64:ff9b::8.8.8.8 ::ffff:8.8.8.8 fe00::1 2001:db9::1 101::1
    )

    test "every private, loopback, link-local and non-routable IPv6 form is refused" do
      for text <- @blocked do
        {:ok, address} = :inet.parse_address(String.to_charlist(text))
        assert Proxy.private?(address), "#{text} (#{inspect(address)}) was not refused"
      end
    end

    test "a public IPv6 address is not refused" do
      for text <- @allowed do
        {:ok, address} = :inet.parse_address(String.to_charlist(text))
        refute Proxy.private?(address), "#{text} (#{inspect(address)}) was wrongly refused"
      end
    end

    test "an IPv6 form embedding a blocked IPv4 address is refused through the IPv4 policy" do
      # Each of these is a different spelling of the cloud metadata address.
      # Judging them on the IPv6 ranges alone would call every one public.
      for text <- [
            "::ffff:169.254.169.254",
            "::169.254.169.254",
            "2002:a9fe:a9fe::",
            "64:ff9b::169.254.169.254"
          ] do
        {:ok, address} = :inet.parse_address(String.to_charlist(text))
        assert Proxy.private?(address), "#{text} reaches 169.254.169.254 and was not refused"
      end
    end

    test "one blocked answer refuses the host, whatever the others are" do
      # The rule the ordering of a resolver's answers must not decide.
      public = {2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888}
      private = {0, 0, 0, 0, 0, 0, 0, 1}

      assert Proxy.blocked([public]) == []
      assert Proxy.blocked([{8, 8, 8, 8}, public]) == []
      assert Proxy.blocked([public, private]) == [private]
      assert Proxy.blocked([private, public]) == [private]
      assert Proxy.blocked([{8, 8, 8, 8}, private]) == [private]
      assert Proxy.blocked([{127, 0, 0, 1}, public]) == [{127, 0, 0, 1}]
      assert Proxy.blocked([]) == []
    end

    test "the IPv4 policy is unchanged" do
      for text <- ~w(10.1.2.3 172.16.0.1 192.168.1.1 169.254.169.254 100.64.0.1 127.0.0.1 0.0.0.0) do
        {:ok, address} = :inet.parse_address(String.to_charlist(text))
        assert Proxy.private?(address)
      end

      for text <- ~w(140.82.112.3 172.32.0.1 100.128.0.1 8.8.8.8) do
        {:ok, address} = :inet.parse_address(String.to_charlist(text))
        refute Proxy.private?(address)
      end
    end
  end

  describe "the bracketed grammar" do
    test "a CONNECT authority naming an IPv6 literal" do
      assert {:ok, {"::1", 8443}, "[::1]:8443"} =
               HTTP.destination(%{method: "CONNECT", target: "[::1]:8443"})

      assert {:ok, {"2001:db8::1", 443}, _} =
               HTTP.destination(%{method: "CONNECT", target: "[2001:db8::1]:443"})
    end

    test "an unbracketed IPv6 authority is a bad target, not a host called ::1" do
      # Without brackets there is no telling which colon is the separator,
      # so guessing would be guessing about where a request goes.
      assert {:error, :bad_target} = HTTP.destination(%{method: "CONNECT", target: "::1:8443"})
      assert {:error, :bad_target} = HTTP.destination(%{method: "CONNECT", target: "[::1]"})
    end

    test "an absolute-form URI naming an IPv6 literal, with and without a port" do
      assert {:ok, {"::1", 8080}, "/x?y=1"} =
               HTTP.destination(%{method: "GET", target: "http://[::1]:8080/x?y=1"})

      assert {:ok, {"::1", 80}, "/x"} =
               HTTP.destination(%{method: "GET", target: "http://[::1]/x"})
    end

    test "a rule pattern for an IPv6 literal is bracketed, with or without a port" do
      assert Injector.matches?("[::1]", "::1", 443, "/x")
      assert Injector.matches?("[::1]:8443", "::1", 8443, "/x")
      refute Injector.matches?("[::1]:8443", "::1", 443, "/x")
      assert Injector.matches?("[2001:db8::1]", "2001:db8::1", 443, "/x")
      assert Injector.matches?("[::1]/api", "::1", 443, "/api/v1")
      refute Injector.matches?("[::1]/api", "::1", 443, "/other")

      # A bare literal is not a pattern: the first colon reads as the port
      # separator, so it matches nothing rather than matching by accident.
      refute Injector.matches?("::1", "::1", 443, "/x")
    end

    test "host_matches?/3 handles a bracketed pattern with a path" do
      assert Injector.host_matches?("[::1]:8443/api", "::1", 8443)
      refute Injector.host_matches?("[::1]:8443/api", "::1", 443)
    end

    test "a bracketed pattern that is never closed matches nothing" do
      # An unclosed bracket is taken literally rather than being read as a
      # host called `[` with the port `:1`, which would match somewhere
      # else by accident. No host ever arrives bracketed — `destination/1`
      # strips them — so taking it literally matches nothing.
      refute Injector.matches?("[::1", "::1", 443, "/x")
    end

    test "the IPv4 and hostname grammar is unchanged" do
      assert Injector.matches?("example.com", "example.com", 443, "/")
      assert Injector.matches?("example.com:8443", "example.com", 8443, "/")
      assert Injector.matches?("127.0.0.1:8443", "127.0.0.1", 8443, "/")
      assert Injector.matches?("*.example.com", "a.example.com", 443, "/")
    end
  end

  describe "certificates for an address" do
    test "a literal host gets an iPAddress SAN, in the octets RFC 5280 asks for" do
      root = CA.root(seed())

      for {host, octets} <- [
            {"127.0.0.1", <<127, 0, 0, 1>>},
            {"::1", <<0::120, 1>>},
            {"2001:db8::1", <<0x20, 0x01, 0x0D, 0xB8, 0::88, 1>>}
          ] do
        sans = sans(CA.leaf(host, root))
        assert sans == [iPAddress: octets], "#{host} got #{inspect(sans)}"
      end
    end

    test "a name still gets a dNSName SAN" do
      assert [dNSName: ~c"example.com"] = sans(CA.leaf("example.com", CA.root(seed())))
    end

    defp sans(leaf_opts) do
      {:Extension, _oid, _critical, sans} =
        leaf_opts[:cert]
        |> X509.Certificate.from_der!()
        |> X509.Certificate.extension(:subject_alt_name)

      sans
    end
  end

  # These bind a listener on `::1`. `test_helper.exs` excludes the tag on a
  # host without an IPv6 loopback, so they skip there rather than fail.
  describe "an IPv6 origin, end to end" do
    @describetag :ipv6

    # TestMITMForwardIPv6PreservesHostHeader
    test "an absolute-form request to a bracketed IPv6 literal reaches the origin" do
      ctx = start_rig()
      port = start_http_origin_v6()

      token =
        put_session(ctx, %Session{
          rules: [
            %Rule{name: "v6", pattern: "[::1]", scheme: :bearer, credential: "ghp_real"}
          ],
          unmatched_host_policy: :deny,
          expires_at: DateTime.add(DateTime.utc_now(), 600, :second)
        })

      {:ok, tcp} = :gen_tcp.connect(~c"127.0.0.1", ctx.proxy_port, [:binary, active: false])

      :ok =
        :gen_tcp.send(
          tcp,
          "GET http://[::1]:#{port}/v6 HTTP/1.1\r\nHost: [::1]:#{port}\r\n" <>
            "Proxy-Authorization: #{proxy_auth(token)}\r\n" <>
            "Authorization: Bearer __placeholder__\r\n\r\n"
        )

      reply = read_until_closed(tcp)
      assert reply =~ "HTTP/1.1 200"

      [_, body] = String.split(reply, "\r\n\r\n", parts: 2)
      echoed = Jason.decode!(body)

      assert echoed["path"] == "/v6"
      assert echoed["headers"]["authorization"] == "Bearer ghp_real"

      # The brackets survive to the origin: `Host: ::1:8080` would be
      # ambiguous, and it is the client's header the proxy forwards.
      assert echoed["headers"]["host"] == "[::1]:#{port}"
    end

    test "a CONNECT tunnel to a bracketed IPv6 literal completes both handshakes" do
      ctx = start_rig()
      port = start_https_origin_v6(ctx.origin_tls)
      token = put_session(ctx, bearer_session("ghp_real"))

      {tcp, reply} = connect(ctx, "[::1]:#{port}", proxy_auth(token))
      assert reply =~ "HTTP/1.1 200", "CONNECT to an IPv6 literal answered #{inspect(reply)}"

      # The sandbox's side: the leaf the proxy signs for `::1` has to
      # validate as an IP certificate, not as a name.
      {:ok, client} =
        :ssl.connect(
          tcp,
          [
            verify: :verify_peer,
            cacerts: [ctx.ca_der],
            server_name_indication: :disable,
            customize_hostname_check: [
              match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
            ],
            active: false
          ],
          5_000
        )

      :ok = :ssl.send(client, "GET /tunnelled HTTP/1.1\r\nHost: [::1]\r\n\r\n")
      assert recv_until(client, "\"path\"") =~ "/tunnelled"
    end

    test "an origin whose certificate names a different address is refused" do
      # The regression this exists for: `server_name_indication: :disable`
      # would make an origin named by address verify against nothing at
      # all, so a certificate for any address would be accepted. Every
      # functional test still passes with that bug, because the leaf the
      # rig hands out happens to be the right one. This one does not.
      wrong = <<0x20, 0x01, 0x0D, 0xB8, 0::88, 1>>
      {ca, tls} = origin_tls_for_address(wrong)

      ctx = start_rig(extra_cacerts: [X509.Certificate.to_der(ca)])
      port = start_https_origin_v6(tls)
      token = put_session(ctx, bearer_session("x"))

      # The CA is trusted; the identity is not the one dialed. A 502 means
      # the proxy checked. A 200 means it did not.
      {_tcp, reply} = connect(ctx, "[::1]:#{port}", proxy_auth(token))
      assert reply =~ "HTTP/1.1 502", "upstream identity was not verified: #{inspect(reply)}"
    end

    test "an origin whose certificate names the address dialed is accepted" do
      # The other half: verification is on, not merely failing everything.
      {ca, tls} = origin_tls_for_address(<<0::120, 1>>)

      ctx = start_rig(extra_cacerts: [X509.Certificate.to_der(ca)])
      port = start_https_origin_v6(tls)
      token = put_session(ctx, bearer_session("x"))

      {_tcp, reply} = connect(ctx, "[::1]:#{port}", proxy_auth(token))
      assert reply =~ "HTTP/1.1 200"
    end

    test "an IPv6 loopback upstream is refused when the guard is on" do
      ctx = start_rig(allow_private_upstreams: false)
      port = start_http_origin_v6()
      token = put_session(ctx, bearer_session("x"))

      {_tcp, reply} = connect(ctx, "[::1]:#{port}", proxy_auth(token))
      assert reply =~ "HTTP/1.1 403"
    end

    test "a name resolving into both families is refused on either answer" do
      # `localhost` answers in both families, so this is the multi-answer
      # path on the wire: every answer is vetted before any dial, and one
      # blocked answer refuses the host. What the resolver returns exactly
      # is the host's business — a runner may list 127.0.0.1 twice — so
      # this asserts the shape the rule needs, not the answer.
      {:ok, v4} = :inet.getaddrs(~c"localhost", :inet)
      {:ok, v6} = :inet.getaddrs(~c"localhost", :inet6)
      addresses = Enum.uniq(v4 ++ v6)

      assert length(addresses) > 1, "localhost answers once here: #{inspect(addresses)}"
      assert Proxy.blocked(addresses) == addresses

      ctx = start_rig(allow_private_upstreams: false)
      token = put_session(ctx, bearer_session("x"))

      {_tcp, reply} = connect(ctx, "localhost:#{ctx.https_port}", proxy_auth(token))
      assert reply =~ "HTTP/1.1 403"
    end
  end
end
