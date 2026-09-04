defmodule Managoat.Broker.Injector do
  @moduledoc """
  The header rewrite the proxy applies to one request.

  A `Managoat.Broker.Rule` binds a host pattern to an auth shape and a
  credential. When a request matches a rule that sets a header, the
  request's own copy of that header is dropped whatever it carried (the
  placeholder, usually) and the real one is written in its place.
  `proxy-authorization`, which carried the session token from the sandbox,
  never reaches the origin. When no rule matches, the session's
  `unmatched_host_policy` decides: `:passthrough` sends the request
  untouched, `:deny` refuses it.

  Several rules may match. The **most specific** one that sets a header is
  the one that does; every matched `:substitute` rule applies, in the order
  the host declared them, to the header values *and* to the request target.

  ## Which rule sets the header

  Specificity is four ordered tiers, and the first one that separates two
  rules decides:

    1. an exact host beats a `*.` wildcard — even when the wildcard rule
       carries the longer path, because a rule naming this host is a
       statement about this host and a wildcard is a default;
    2. within a host tier, a pattern that pins a port beats one that
       matches any port;
    3. within a host and port tier, the longest literal path prefix wins
       (a trailing `*` is not part of it);
    4. declaration order breaks what is left — so a list of
       equally-specific rules resolves exactly as it always did.

  Defaults first with overrides appended is the natural way to build a rule
  list, and under declaration order the appended override lost: the request
  went out with the *wrong* credential and succeeded, and the event named
  the rule that had won, so even the audit log looked fine. These are Agent
  Vault's tiers (`MatchService`, internal/broker/broker.go).

  `:passthrough` never takes part. It is how a host is allowed under
  `deny`, not a way to suppress injection, so an exact-host allowlist entry
  beside a wildcard rule that injects does not stop the credential being
  attached — a host that means "reach this untouched" says so by not
  writing a rule that injects. `:substitute` does not take part either:
  scoring picks one rule, and several placeholders can legitimately appear
  in one request, so every matched substitute rule applies in declaration
  order.

  ## Substitution and the request target

  A `:substitute` rule reaches the target as well as the headers, so a
  credential a client puts in the URL — the bot API shape,
  `/bot<token>/sendMessage`, or an `?key=` a runtime fills in — is brokered
  like any other. A tenant declares its placeholder and nothing more; it
  does not have to tell the proxy where the client put it.

  Rules are matched against the target the client sent, and the rewritten
  target is only what gets forwarded. Telemetry is derived from the
  original, so a placeholder in a path is logged as the placeholder and a
  placeholder in a query is not logged at all (`Managoat.Broker.Proxy`
  drops queries from the event).

  The credential replaces the placeholder byte for byte: nothing is
  percent-encoded on the way in and nothing is decoded. A credential that
  cannot be written where its placeholder sits is refused instead, as
  `{:error, {:unsafe_credential, rule_name, surface}}`: a control
  character or a space would split the request line in a `:target`, and CR
  or LF would end the field and start another in a `:header`. A space in a
  header value is ordinary and is not refused.

  ## A credential the host could not supply

  A matched `:bearer`, `:basic`, `:api_key` or `:custom` rule builds its
  header *from* the credential, so a rule holding `nil` — or anything that
  is not the shape the scheme needs — has no header to write. That is
  refused, as `{:error, {:credential_missing, rule_name, scheme}}`, and
  `Managoat.Broker.Proxy` answers `502`: the broker failed to obtain a
  credential, which is not the client doing anything wrong, and an agent
  should retry once it is provisioned rather than conclude it is not
  allowed. It is the shape a `Store` hands back when provisioning is
  incomplete, when decryption failed, or when an OAuth grant was never
  connected.

  The schemes that carry a placeholder rather than build a header are
  deliberately not refused: a `:substitute` rule with no credential
  forwards its placeholder as written, and a `:custom` template leaves a
  `{{ KEY }}` it holds no value for alone. In both the origin refuses a
  visible placeholder, which is the clearer failure.
  """

  alias Managoat.Broker.{Rule, Session}

  @hop_by_hop ~w(proxy-authorization proxy-connection)
  @template_re ~r/\{\{\s*([A-Z][A-Z0-9_]*)\s*\}\}/

  @type header :: {String.t(), String.t()}

  @doc """
  Rewrite `headers` and the request `target` for a request to
  `host`:`port`. Returns `{:ok, headers, target, rule}` with the target to
  forward and the **rule** that applied — the one that set the header, or
  the first matched rule when none did, and `nil` when no rule matched —
  `{:error, :denied}`, `{:error, {:unsafe_credential, rule_name,
  surface}}` when a credential could not be written into the target, or
  `{:error, {:credential_missing, rule_name, scheme}}` when a matched rule
  that sets a header holds no usable credential.

  The rule comes back whole rather than by name because its `scheme` is
  what says whether anything was attached: a matched `:passthrough` rule
  and a matched `:bearer` rule are both "a rule applied", and only the
  scheme separates them. Names are not unique, so a caller handed one
  could not look the rest up.

  `target` is the request target as the client sent it, origin-form
  (`/path?query`). Rules match against it unchanged; the returned target
  is the one to forward, which differs only where a `:substitute` rule
  applied.
  """
  @spec inject([header()], String.t(), :inet.port_number(), String.t(), Session.t()) ::
          {:ok, [header()], String.t(), Rule.t() | nil}
          | {:error, :denied}
          | {:error, {:unsafe_credential, String.t() | nil, :target | :header}}
          | {:error, {:unusable_placeholder, String.t() | nil}}
          | {:error, {:credential_missing, String.t() | nil, Rule.scheme()}}
  def inject(headers, host, port, target, %Session{} = session) do
    headers = Enum.reject(headers, fn {k, _} -> String.downcase(k) in @hop_by_hop end)

    case Enum.filter(session.rules, &matches?(&1.pattern, host, port, target)) do
      [] ->
        if session.unmatched_host_policy == :deny,
          do: {:error, :denied},
          else: {:ok, headers, target, nil}

      [first | _] = matched ->
        substitutions = Enum.filter(matched, &(&1.scheme == :substitute))

        case unusable(substitutions) || unsafe(substitutions, headers, target) do
          nil ->
            headers = Enum.reduce(substitutions, headers, &substitute_headers/2)
            target = Enum.reduce(substitutions, target, &substitute_target/2)

            case header_rule(matched) do
              nil ->
                {:ok, headers, target, first}

              rule ->
                case put_auth(headers, rule) do
                  {:ok, headers} -> {:ok, headers, target, rule}
                  :error -> {:error, {:credential_missing, rule.name, rule.scheme}}
                end
            end

          {rule, :placeholder} ->
            {:error, {:unusable_placeholder, rule.name}}

          {rule, surface} ->
            {:error, {:unsafe_credential, rule.name, surface}}
        end
    end
  end

  @doc """
  Is this usable as a `:substitute` placeholder?

  Substitution is a literal find-and-replace over header values and the
  request target, so a placeholder that occurs in ordinary text rewrites
  ordinary text. `"id"` would rewrite every `id` in every matching path,
  and `"account_sid"` is a real field name that appears in URLs — the
  credential would land somewhere nobody chose, and nothing would raise.

  A usable placeholder therefore:

    * is at least four characters,
    * contains at least one letter or digit, and
    * carries a boundary — it begins or ends with `__`, or contains a
      character outside `[A-Za-z0-9_]`.

  `__github_token__`, `sk-__openai_api_key__` and `{{TOKEN}}` pass;
  `id`, `token` and `account_sid` do not.

  Hosts should call this when they build a session, so a bad rule fails
  where it is written rather than on every request it would have matched.
  `inject/5` enforces it either way.
  """
  @spec valid_placeholder?(term()) :: boolean()
  def valid_placeholder?(placeholder) when is_binary(placeholder) do
    byte_size(placeholder) >= 4 and
      String.match?(placeholder, ~r/[A-Za-z0-9]/) and
      (String.starts_with?(placeholder, "__") or String.ends_with?(placeholder, "__") or
         String.match?(placeholder, ~r/[^A-Za-z0-9_]/))
  end

  def valid_placeholder?(_placeholder), do: false

  @doc "Does the host part of a rule `pattern` match this host and port, whatever the path?"
  @spec host_matches?(String.t(), String.t(), :inet.port_number()) :: boolean()
  def host_matches?(pattern, host, port) when is_binary(pattern) do
    {host_part, _path_part} = split_pattern(pattern)
    matches?(host_part, host, port, "/")
  end

  @doc """
  Does a rule `pattern` (`host[:port][/path]`) match this request? An IPv6
  literal is bracketed — `[::1]` or `[::1]:8443` — because otherwise there
  is no telling which colon is the port separator.

  An address is compared by its value, not its spelling: `[::1]`,
  `[::0001]` and `[0:0:0:0:0:0:0:1]` are one pattern. A name is compared
  case-insensitively, as before.
  """
  @spec matches?(String.t(), String.t(), :inet.port_number(), String.t()) :: boolean()
  def matches?(pattern, host, port, path) when is_binary(pattern) do
    {host_part, path_part} = split_pattern(pattern)
    {host_pattern, port_pattern} = split_host_pattern(host_part)

    host_pattern_matches?(canonical(host_pattern), canonical(host)) and
      port_matches?(port_pattern, port) and path_matches?(path_part, path)
  end

  # Which matched rule sets the header: the most specific one, not the one
  # the host happened to declare first. Rules are built defaults-first with
  # overrides appended, which is the natural way to write them, and under
  # declaration order that appended override lost — silently, and with the
  # wrong credential on a request that then *succeeded*. Agent Vault scored
  # its services the same way (`MatchService`, internal/broker/broker.go)
  # and these are its tiers.
  #
  # `:passthrough` is not a candidate, exactly as before. It is how a host
  # is allowed under `deny`, not a way to suppress injection, so an
  # exact-host allowlist entry beside a wildcard `:bearer` must not stop the
  # credential being attached — a host that means "reach this untouched"
  # says it by not writing a rule that injects. `:substitute` is not a
  # candidate either: every matched substitute rule applies, in declaration
  # order, because several placeholders can legitimately appear in one
  # request, and scoring picks one rule.
  defp header_rule(matched) do
    candidates =
      matched
      |> Enum.with_index()
      |> Enum.filter(fn {rule, _index} -> rule.scheme not in [:substitute, :passthrough] end)

    case candidates do
      [] -> nil
      _ -> candidates |> Enum.min_by(&specificity/1) |> elem(0)
    end
  end

  # The sort key, most specific first. Every component is written so that
  # ascending term order *is* descending specificity: `false` sorts before
  # `true`, so an exact host beats a wildcard and a pinned port beats any
  # port; the path length is negated, so the longest literal prefix wins;
  # and the declaration index breaks what is left, so a list of
  # equally-specific rules resolves exactly as it always did.
  #
  # The tiers are ordered, not added together: an exact host wins even when
  # the wildcard rule carries the longer path, because a rule naming this
  # host is a statement about this host and a wildcard is a default.
  defp specificity({%Rule{pattern: pattern}, index}) do
    {host_part, path_part} = split_pattern(pattern)
    {host_pattern, port_pattern} = split_host_pattern(host_part)

    {wildcard_host?(host_pattern), any_port?(port_pattern), -path_length(path_part), index}
  end

  defp wildcard_host?("*." <> _suffix), do: true
  defp wildcard_host?(_host_pattern), do: false

  defp any_port?(port_pattern), do: is_nil(port_pattern)

  # How much literal path a pattern pins. The trailing `*` is not part of
  # it: `/api/*` and `/api` both commit to `/api`, and what separates them
  # is which requests they match, not how specific they are.
  defp path_length(nil), do: 0
  defp path_length(path), do: path |> String.trim_trailing("*") |> byte_size()

  defp split_pattern(pattern) do
    case String.split(pattern, "/", parts: 2) do
      [host_part] -> {host_part, nil}
      [host_part, path] -> {host_part, "/" <> path}
    end
  end

  # An address has many spellings and one meaning: `::1`, `::0001` and
  # `0:0:0:0:0:0:0:1` are the same host, and `10.0.0.1` is not
  # `10.00.00.01`. A pattern that matched only the spelling the operator
  # happened to type would fail silently — the credential simply would not
  # be attached — so both sides go through the resolver's own text form
  # first. Anything that is not an address is a name, and names are matched
  # case-insensitively as before.
  defp canonical(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> address |> :inet.ntoa() |> List.to_string()
      {:error, _} -> String.downcase(host)
    end
  end

  # `host`, `host:port`, `[v6]` or `[v6]:port`. An IPv6 literal is full of
  # colons, so the colon can only be the port separator once brackets say
  # where the host ends — which is why a bare literal has to be bracketed
  # too. `[::1]` and `[::1]:8443` are both patterns; `::1` is not, and is
  # read as the host `:` with the port `:1`, which matches nothing.
  defp split_host_pattern("[" <> rest) do
    case String.split(rest, "]", parts: 2) do
      [host, ":" <> port] -> {host, port}
      [host, ""] -> {host, nil}
      _ -> {"[" <> rest, nil}
    end
  end

  defp split_host_pattern(host_part) do
    case String.split(host_part, ":", parts: 2) do
      [h] -> {h, nil}
      [h, p] -> {h, p}
    end
  end

  defp host_pattern_matches?("*." <> suffix, host), do: String.ends_with?(host, "." <> suffix)
  defp host_pattern_matches?(pattern, host), do: pattern == host

  defp port_matches?(nil, _port), do: true
  defp port_matches?(pattern, port), do: pattern == Integer.to_string(port)

  defp path_matches?(nil, _path), do: true

  defp path_matches?(pattern, path) do
    path = path |> String.split("?", parts: 2) |> hd()

    if String.ends_with?(pattern, "*"),
      do: String.starts_with?(path, String.trim_trailing(pattern, "*")),
      else: path == pattern or String.starts_with?(path, pattern <> "/")
  end

  defp put_auth(headers, %Rule{scheme: :bearer, credential: token}) when is_binary(token) do
    {:ok, replace(headers, "authorization", "Bearer " <> token)}
  end

  defp put_auth(headers, %Rule{scheme: :basic, credential: {user, pass}})
       when is_binary(user) and is_binary(pass) do
    {:ok, replace(headers, "authorization", "Basic " <> Base.encode64(user <> ":" <> pass))}
  end

  defp put_auth(headers, %Rule{scheme: :api_key, credential: value} = rule)
       when is_binary(value) do
    {:ok, replace(headers, rule.header || "Authorization", (rule.prefix || "") <> value)}
  end

  defp put_auth(headers, %Rule{scheme: :custom, template: templates, credential: creds})
       when is_map(templates) and is_map(creds) do
    {:ok,
     Enum.reduce(templates, headers, fn {name, template}, acc ->
       replace(acc, name, render(template, creds))
     end)}
  end

  # A matched rule whose credential is missing, or is not the shape its
  # scheme builds a header from. The host resolved this rule at session
  # creation and got nothing back: provisioning is incomplete, decryption
  # failed, or an OAuth grant was never connected. There is no header to
  # write, so the request is refused rather than sent without one — sending
  # it unauthenticated would turn a broker failure into an origin's `401`,
  # which reads as the agent's credential being wrong.
  #
  # `:substitute` is deliberately not here: a placeholder with no credential
  # is forwarded as written, because the origin refusing a visible
  # placeholder is the clearer failure. `:custom` leaves an unfilled
  # `{{ KEY }}` alone for the same reason; it lands here only when it has no
  # credential map at all.
  defp put_auth(_headers, %Rule{}), do: :error

  # Every `{{ KEY }}` the rule holds a value for; one it does not is left
  # as written, which the origin then refuses, rather than sent empty.
  defp render(template, creds) do
    Regex.replace(@template_re, template, fn whole, key ->
      Map.get(creds, key, whole)
    end)
  end

  defp substitute_headers(%Rule{placeholder: placeholder, credential: value}, headers)
       when is_binary(placeholder) and placeholder != "" and is_binary(value) do
    Enum.map(headers, fn {k, v} -> {k, String.replace(v, placeholder, value)} end)
  end

  defp substitute_headers(_rule, headers), do: headers

  # The credential goes into the target byte for byte: nothing is
  # percent-encoded on the way in and nothing is decoded. The proxy cannot
  # know which URI component a placeholder sits in, nor what encoding the
  # origin expects, and the canonical case says verbatim is right — a
  # Telegram bot token is `<digits>:<rest>` in a path segment, where `:` is
  # legal unencoded and `%3A` would be a different URL. A tenant whose
  # credential needs percent-encoding declares it already encoded.
  defp substitute_target(%Rule{placeholder: placeholder, credential: value}, target)
       when is_binary(placeholder) and placeholder != "" and is_binary(value) do
    String.replace(target, placeholder, value)
  end

  defp substitute_target(_rule, target), do: target

  # The first matched rule whose placeholder is not usable as one. Checked
  # whether or not it currently occurs anywhere: a placeholder like `id` is
  # dangerous exactly when it turns up in a path nobody was thinking about,
  # so waiting until it does would report the problem on the request that
  # already leaked the credential. Refusing every request the rule matches
  # is loud, and a rule that rewrites arbitrary text should be loud.
  defp unusable(rules) do
    case Enum.find(rules, fn %Rule{placeholder: p} -> not valid_placeholder?(p) end) do
      nil -> nil
      rule -> {rule, :placeholder}
    end
  end

  # The first rule whose credential cannot be written where its placeholder
  # sits, and which surface that was. Nil when every substitution is safe.
  #
  # Both surfaces are checked, and they do not have the same rule. In a
  # request target, verbatim substitution is safe for the reserved
  # characters — `/`, `?`, `#`, `&`, `=` and the rest change which resource
  # the origin sees, and choosing the placeholder's position is the
  # tenant's business — but not for the characters a target cannot hold at
  # all: CR or LF would end the request line and start a second request,
  # and a space would end the target and make the rest the HTTP version. In
  # a header value CR and LF are the whole danger, because they end the
  # field and start another one; a space is ordinary there, and a signature
  # header is full of them.
  #
  # Neither is encoded around. Encoding a credential would send the origin
  # something it cannot use, quietly, which is worse than a refusal that
  # names the rule.
  #
  # Only rules that actually reach a surface are checked against it, so a
  # header credential holding a space is not refused for a target rule it
  # never touches.
  defp unsafe(rules, headers, target) do
    Enum.find_value(rules, fn
      %Rule{placeholder: p, credential: v} = rule
      when is_binary(p) and p != "" and is_binary(v) ->
        cond do
          String.contains?(target, p) and not target_safe?(v) ->
            {rule, :target}

          Enum.any?(headers, fn {_k, hv} -> String.contains?(hv, p) end) and crlf?(v) ->
            {rule, :header}

          true ->
            nil
        end

      _ ->
        nil
    end)
  end

  defp target_safe?(value), do: not String.match?(value, ~r/[\x00-\x20\x7f]/)

  defp crlf?(value), do: String.contains?(value, "\r") or String.contains?(value, "\n")

  defp replace(headers, name, value) do
    down = String.downcase(name)
    [{name, value} | Enum.reject(headers, fn {k, _} -> String.downcase(k) == down end)]
  end
end
