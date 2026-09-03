defmodule Managoat.Broker.CATest do
  use ExUnit.Case, async: true

  alias Managoat.Broker.{CA, Certs}

  @seed :crypto.hash(:sha256, "a fixed seed for the CA tests")

  # What a trust anchor is matched on. The self-signature is not in here:
  # ECDSA signing is randomised, so it differs per derivation, and no client
  # consults it.
  defp anchor(der) do
    cert = X509.Certificate.from_der!(der)

    {X509.Certificate.subject(cert), X509.Certificate.public_key(cert),
     X509.Certificate.serial(cert)}
  end

  test "the root is derived from the seed: same seed, same anchor" do
    assert anchor(CA.der(@seed)) == anchor(CA.der(@seed))
  end

  test "a leaf signed by a re-derivation still chains to the first root" do
    root = CA.der(@seed)
    [cert: leaf, key: _] = CA.leaf("github.com", CA.root(@seed))
    assert {:ok, _} = :public_key.pkix_path_validation(root, [leaf], [])
  end

  test "a different seed is a different CA" do
    refute anchor(CA.der(@seed)) == anchor(CA.der(:crypto.strong_rand_bytes(32)))
  end

  test "the root is a CA and a leaf for a host chains to it" do
    root = CA.der(@seed)
    [cert: leaf, key: {:ECPrivateKey, _}] = CA.leaf("api.github.com", CA.root(@seed))

    assert {:ok, _} = :public_key.pkix_path_validation(root, [leaf], [])

    otp = X509.Certificate.from_der!(leaf)
    assert X509.Certificate.subject(otp) |> X509.RDNSequence.to_string() =~ "api.github.com"

    {:Extension, _, _, names} = X509.Certificate.extension(otp, :subject_alt_name)
    assert {:dNSName, ~c"api.github.com"} in names
  end

  test "the PEM is one certificate" do
    assert [{:Certificate, _, :not_encrypted}] = :public_key.pem_decode(CA.pem(@seed))
  end

  test "a seed that is not 32 bytes is refused by name" do
    assert_raise ArgumentError, ~r/32 bytes/, fn -> CA.root("short") end
  end

  describe "Certs" do
    test "caches a leaf per host and hands the root back" do
      table = Certs.new(@seed)

      assert anchor(Certs.ca_der(table)) == anchor(CA.der(@seed))
      assert Certs.ca_pem(table) =~ "BEGIN CERTIFICATE"

      first = Certs.for_host(table, "api.github.com")
      assert first == Certs.for_host(table, "api.github.com")
      refute first == Certs.for_host(table, "github.com")

      assert {:ok, _} =
               :public_key.pkix_path_validation(Certs.ca_der(table), [first[:cert]], [])
    end

    test "holds at most max_leaves, and the least recently used goes first" do
      # The key is the host from a sandbox's own CONNECT line, so what the
      # cache holds is chosen by the sandbox: a wildcard DNS record aimed at
      # one address makes every `*.attacker.example` a distinct entry.
      table = Certs.new(@seed, 3)
      assert Certs.cached_leaves(table) == 0

      a = Certs.for_host(table, "a.example")
      b = Certs.for_host(table, "b.example")
      c = Certs.for_host(table, "c.example")
      assert Certs.cached_leaves(table) == 3

      # `a` is used again, so the least recently used is now `b`.
      assert Certs.for_host(table, "a.example") == a

      d = Certs.for_host(table, "d.example")
      assert Certs.cached_leaves(table) == 3

      # A host still in use keeps its leaf across evictions of others: the
      # cache is not a re-signing treadmill.
      assert Certs.for_host(table, "a.example") == a
      assert Certs.for_host(table, "c.example") == c
      assert Certs.for_host(table, "d.example") == d

      # `b` went, so it comes back as a newly signed leaf. Last, because
      # signing it evicts whatever is least recently used by then.
      refute Certs.for_host(table, "b.example") == b
    end

    test "a flood of distinct hosts stops at the cap" do
      table = Certs.new(@seed, 8)

      for i <- 1..40, do: Certs.for_host(table, "h#{i}.attacker.example")

      assert Certs.cached_leaves(table) == 8

      # And the root is still there to sign with, which the leaf count is
      # deliberately not counting.
      assert Certs.ca_pem(table) =~ "BEGIN CERTIFICATE"
    end
  end
end
