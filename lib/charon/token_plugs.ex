defmodule Charon.TokenPlugs do
  @moduledoc """
  The plugs in this module (and its submodules) can be used to verify tokens.
  The token's presence, signature, expiration and any claims can be checked.
  Additionally, the token's session can be loaded and, in case of a refresh token,
  it can be verified that it matches the session.

  In case of validation errors, the plugs add an "auth error" to the conn,
  but don't raise or halt the connection immediately.
  This property can be used to support endpoints
  that work with- or without authentication, for example,
  or if you want to support multiple kinds of tokens.
  The plug `verify_no_auth_error/2` can be used to actually do something if there is an error.
  All the plugs short-circuit, meaning that they immediately
  return the connection if there are errors.

  Similarly, in case of successful validation, the token payload, user id and session are not assigned to the conn immediately. You can use `Charon.TokenPlugs.PutAssigns` to customize what is assigned and how.

  Using the plugs in these module, you can construct your own verification pipeline
  using either Plug.Builder or standard Phoenix router pipelines.
  Here are two examples for access- and refresh tokens, respectively,
  that should be a good baseline for your own pipelines.

  ## Access tokens

      defmodule MyApp.AccessTokenPipeline do
        use Plug.Builder

        @config Charon.Config.from_enum(Application.compile_env!(:my_app, :charon))

        plug :get_token_from_auth_header
        plug :get_token_from_cookie, @config.access_cookie_name
        plug :verify_token_signature, @config
        plug :verify_token_nbf_claim
        plug :verify_token_exp_claim
        plug :verify_token_claim_equals, type: "access"
        plug :emit_telemetry
        plug :verify_no_auth_error, &MyApp.TokenErrorHandler.on_error/2
        plug Charon.TokenPlugs.PutAssigns
      end

  ## Refresh tokens

      defmodule MyApp.RefreshTokenPipeline do
        use Plug.Builder

        @config Charon.Config.from_enum(Application.compile_env!(:my_app, :charon))

        plug :get_token_from_auth_header
        plug :get_token_from_cookie, @config.refresh_cookie_name
        plug :verify_token_signature, @config
        plug :verify_token_nbf_claim
        plug :verify_token_exp_claim
        plug :verify_token_claim_equals, type: "refresh"
        plug :load_session, @config
        plug :verify_token_fresh, 10
        plug :emit_telemetry
        plug :verify_no_auth_error, &MyApp.TokenErrorHandler.on_error/2
        plug Charon.TokenPlugs.PutAssigns
      end
  """
  alias Plug.Conn
  import Conn, except: [put_private: 3]

  alias Charon.{Config, TokenFactory, Internal, SessionStore}
  use Internal.Constants
  import Internal
  import Charon.Utils

  @typedoc """
  The name of a token claim to verify.

  Atoms are automatically converted to strings (e.g., `:type` becomes `"type"`).
  This allows for a more ergonomic API when specifying claims.
  """
  @type claim_name :: String.t() | atom()

  @typedoc """
  A verifier function for custom claim validation.

  The function receives the connection and the claim value, and must return:
  - The connection (possibly modified) if validation succeeds
  - An error message string if validation fails
  """
  @type verifier :: (Conn.t(), any() -> Conn.t() | binary())

  @typedoc """
  A single claim name paired with its expected/comparison value.
  """
  @type claim_and_expectation :: {claim_name(), any()}

  @typedoc """
  One or more claims with their expected/comparison values.

  Can be provided as:
  - A single tuple: `{"type", "access"}` or `{:type, "access"}`
  - A keyword list: `[type: "access", role: "admin"]`
  - A map: `%{type: "access", role: "admin"}`
  - A list of tuples: `[{"type", "access"}, {"role", "admin"}]`
  """
  @type claims_and_expectations ::
          claim_and_expectation() | [claim_and_expectation()] | %{claim_name() => any()}

  @doc """
  Get a bearer token from the `authorization` header.

  Extracts tokens from headers in the format `"Bearer <token>"` or `"Bearer: <token>"`.
  If a valid token is found, it's stored in the connection's private state along with
  the transport type (`:bearer`).

  ## Doctests / examples

      iex> conn()
      ...> |> put_req_header("authorization", "Bearer super.secure.token")
      ...> |> get_token_from_auth_header([])
      ...> |> Utils.get_bearer_token()
      "super.secure.token"
  """
  @spec get_token_from_auth_header(Conn.t(), any) :: Conn.t()
  def get_token_from_auth_header(conn, _opts) do
    conn
    |> get_req_header("authorization")
    |> case do
      ["Bearer " <> token | _] -> token
      ["Bearer: " <> token | _] -> token
      _ -> nil
    end
    |> case do
      not_found when not_found in [nil, ""] -> conn
      token -> put_private(conn, %{@bearer_token => token, @token_transport => :bearer})
    end
  end

  @doc """
  Get the token or token signature from a cookie.

  If a bearer token was previously found by `get_token_from_auth_header/2`, the cookie contents are appended to it if:
  - the cookie starts with a dot
  - the token ends in a dot (for backwards compatibility)

  If no bearer token was previously found, the cookie contents are used as the full token.

  ## Doctests / examples

      iex> conn()
      ...> |> put_req_cookie("access_cookie", "super.secure.token")
      ...> |> fetch_cookies()
      ...> |> get_token_from_cookie("access_cookie")
      ...> |> Utils.get_bearer_token()
      "super.secure.token"
  """
  @doc since: "3.1.0"
  @spec get_token_from_cookie(Conn.t(), String.t()) :: Conn.t()
  def get_token_from_cookie(conn, _cookie_name) when is_map_key(conn.private, @auth_error),
    do: conn

  def get_token_from_cookie(conn, cookie_name) do
    cookie = Map.get(conn.cookies, cookie_name)
    bearer_token = Map.get(conn.private, @bearer_token)

    cond do
      # there's no cookie
      !cookie ->
        conn

      # there's only a cookie
      !bearer_token ->
        put_private(conn, %{@token_transport => :cookie_only, @bearer_token => cookie})

      # both a cookie and a token present, check to see if we need to concatenate
      # TODO: remove String.ends_with?/2 call after 18-11-2026 (it's there for backwards compatibility)
      match?(<<".", _::binary>>, cookie) or String.ends_with?(bearer_token, ".") ->
        put_private(conn, %{@token_transport => :cookie, @bearer_token => bearer_token <> cookie})

      # ignore the cookie
      true ->
        conn
    end
  end

  @doc """
  Verify that the bearer token found by `get_token_from_auth_header/2` is signed correctly,
  using the configured token factory.

  If verification succeeds, the token payload is stored in the connection's private state.
  If verification fails, an authentication error is set instead.
  """
  @spec verify_token_signature(Conn.t(), Config.t()) :: Conn.t()
  def verify_token_signature(conn, _charon_config) when is_map_key(conn.private, @auth_error),
    do: conn

  def verify_token_signature(conn = %{private: %{@bearer_token => token}}, config) do
    with {:ok, payload} <- TokenFactory.verify(token, config) do
      put_private(conn, %{@now => now(), @bearer_token_payload => payload})
    else
      _ -> set_auth_error(conn, "bearer token signature invalid")
    end
  end

  def verify_token_signature(conn, _), do: set_auth_error(conn, "bearer token not found")

  @doc """
  Verify that the bearer token payload contains a valid `nbf` (not before) claim.

  Must be used after `verify_token_signature/2`.

  Allows for some clock drift (5 seconds).
  """
  @spec verify_token_nbf_claim(Conn.t(), Plug.opts()) :: Conn.t()
  def verify_token_nbf_claim(conn, _opts) do
    verify_claim(conn, "nbf", fn conn, nbf ->
      # allow some clock drift
      if now(conn) >= nbf - 5, do: conn, else: "bearer token not yet valid"
    end)
  end

  @doc """
  Verify that the bearer token payload contains a non-expired `exp` (expires at) claim.

  Must be used after `verify_token_signature/2`.

  Note that a token created by `Charon.SessionPlugs.upsert_session/3` is guaranteed
  to have an exp claim that does not outlive its underlying session.

  Allows for some clock drift (5 seconds).
  """
  @spec verify_token_exp_claim(Conn.t(), Plug.opts()) :: Conn.t()
  def verify_token_exp_claim(conn, _opts) do
    verify_claim(conn, "exp", fn conn, exp ->
      # allow some clock drift
      if now(conn) < exp + 5, do: conn, else: "bearer token expired"
    end)
  end

  @doc """
  Verify that the bearer token payload contains `claim` and that its value is in `expected`.
  Also accepts a map/keyword of claims and lists of expected values.

  Must be used after `verify_token_signature/2`.

  ## Doctests / examples

      iex> conn()
      ...> |> Utils.set_token_payload(%{"uid" => 1, "type" => "access"})
      ...> |> verify_token_claim_in(uid: 1..20, type: ["id", "refresh"])
      ...> |> Utils.get_auth_error()
      "bearer token claim type invalid"
  """
  @spec verify_token_claim_in(Conn.t(), claims_and_expectations()) :: Conn.t()
  def verify_token_claim_in(conn, claims_and_expected) do
    verify_token_claim(conn, expectations_to_verifiers(claims_and_expected, &check_membership/4))
  end

  defp check_membership(conn, claim, claim_value, expected) do
    if claim_value in expected, do: conn, else: "bearer token claim #{claim} invalid"
  end

  @doc """
  Verify that the bearer token payload contains `claim` and that its value is `expected`.
  Also accepts a map/keyword of claims and expected values.

  Must be used after `verify_token_signature/2`.

  ## Doctests / examples

      iex> conn()
      ...> |> Utils.set_token_payload(%{"type" => "access"})
      ...> |> verify_token_claim_equals(type: "refresh")
      ...> |> Utils.get_auth_error()
      "bearer token claim type invalid"
  """
  @spec verify_token_claim_equals(Conn.t(), claims_and_expectations()) :: Conn.t()
  def verify_token_claim_equals(conn, claims_and_expected),
    do: verify_token_claim(conn, expectations_to_verifiers(claims_and_expected, &check_equals/4))

  defp check_equals(conn, claim, claim_value, expected) do
    if claim_value == expected, do: conn, else: "bearer token claim #{claim} invalid"
  end

  @doc """
  Verify that the bearer token payload contains `claim` and that its value matches `verifier`, which receives the conn and the claim value, and must return the conn or an error message.
  Also accepts a map/keyword of claims and verifiers.

  Must be used after `verify_token_signature/2`.

  ## Doctests

      def verify_read_scope(conn, value) do
        if "read" in String.split(value, ","), do: conn, else: "no read scope"
      end

      iex> conn()
      ...> |> Utils.set_token_payload(%{"scope" => "write"})
      ...> |> verify_token_claim(scope: &verify_read_scope/2)
      ...> |> Utils.get_auth_error()
      "no read scope"
  """
  @spec verify_token_claim(
          Conn.t(),
          {claim_name(), verifier()} | %{claim_name() => verifier()} | keyword(verifier())
        ) ::
          Conn.t()
  def verify_token_claim(conn, claims_and_verifiers) do
    for {claim, verifier} <- list_wrap(claims_and_verifiers), reduce: conn do
      conn -> verify_claim(conn, atom_to_string(claim), verifier)
    end
  end

  @doc """
  Emit telemetry events after token verification.

  Should be placed immediately before `verify_no_auth_error/2` in the pipeline.
  See `m:Charon.Telemetry#module-token-events` for details on the emitted events.
  """
  @doc since: "4.0.0"
  @spec emit_telemetry(Conn.t(), Plug.opts()) :: Conn.t()
  def emit_telemetry(conn = %{private: private}, _opts) do
    %{
      session_loaded: is_map_key(private, @session),
      token_transport: Map.get(private, @token_transport)
    }
    |> add_token_metadata(private)
    |> do_emit_telemetry(private)

    conn
  end

  defp add_token_metadata(
         metadata,
         _private = %{
           @bearer_token_payload => %{"type" => type, "sub" => uid, "sid" => sid, "styp" => stype}
         }
       ) do
    Map.merge(metadata, %{token_type: type, user_id: uid, session_id: sid, session_type: stype})
  end

  defp add_token_metadata(metadata, _), do: metadata

  defp do_emit_telemetry(metadata, _private = %{@auth_error => error}) do
    metadata |> Map.put(:error, error) |> Charon.Telemetry.emit_token_invalid()
  end

  defp do_emit_telemetry(metadata, _) do
    Charon.Telemetry.emit_token_valid(metadata)
  end

  @doc """
  Make sure that no previous plug of this module added an auth error.
  In case of an error, `on_error` is called (it should probably halt the connection).

  ## Doctests / examples

      iex> conn = conn()
      iex> verify_no_auth_error(conn, fn _conn, _error -> raise "BOOM" end)

      # on error, send an error response
      iex> on_error = fn conn, error -> conn |> send_resp(401, error) |> halt() end
      iex> %{halted: true, resp_body: "oops!"} =
      ...> conn()
      ...> |> Utils.set_auth_error("oops!")
      ...> |> verify_no_auth_error(on_error)
  """
  @spec verify_no_auth_error(Plug.Conn.t(), (Conn.t(), String.t() -> Conn.t())) ::
          Plug.Conn.t()
  def verify_no_auth_error(conn = %{private: %{@auth_error => error}}, on_error) do
    on_error.(conn, error)
  end

  def verify_no_auth_error(conn, _opts), do: conn

  @doc """
  Fetch the session to which the bearer token belongs.
  Raises on session store error.

  Must be used after `verify_token_signature/2`.

  Requires the token payload to contain `"sub"`, `"sid"`, and `"styp"` claims.
  If the session is found, it's stored in the conn's private state.
  If not found, an authentication error is set.
  """
  @spec load_session(Conn.t(), Config.t()) :: Conn.t()
  def load_session(conn, _charon_config) when is_map_key(conn.private, @auth_error), do: conn

  def load_session(conn = %{private: %{@bearer_token_payload => payload}}, config) do
    with %{"sub" => uid, "sid" => sid, "styp" => type} <- payload,
         session = %{} <- SessionStore.get(sid, uid, String.to_atom(type), config) do
      put_private(conn, @session, session)
    else
      nil -> set_auth_error(conn, "session not found")
      {:error, error} -> raise "could not fetch session: #{inspect(error)}"
      _error -> set_auth_error(conn, "bearer token claim sub, sid or styp not found")
    end
  end

  def load_session(_, _), do: raise("must be used after verify_token_signature/2")

  @doc """
  Verify that the token (either access or refresh) is fresh.

  A token is fresh if it belongs to the *current or previous* refresh generation.
  A generation is a set of tokens that is created within `new_cycle_after` seconds after the first token in the generation is created.
  A token created after `new_cycle_after` seconds starts a new generation.

  It would be simpler to just have a single fresh (refresh) token. However, because of refresh race conditions caused by
  network issues or misbehaving clients, enforcing only a single fresh token causes too many problems in practice.

  In addition to this generation mechanism, 5 seconds of clock drift are allowed.

  Must be used after `load_session/2`. Verify the token type with `verify_token_claim_equals/2`.

  ## Freshness example

  New cycle is created 5 seconds after the generation's first token is created,
  and token TTL is 24h (which is irrelevant in this example).

  | Time | Token | Current gen   | Previous gen  | Fresh   | Comment                                                           |
  |------|-------|---------------|---------------|---------|-------------------------------------------------------------------|
  | 0    | A     | g1 (0): A     | -             | A       | Login, initial token generation g1 of the session is created.     |
  | 10   | B     | g2 (10): B    | g1 (0): A     | A, B    | Refresh after g1 expires, g1 becomes prev gen                     |
  | 12   | C     | g2 (10): B, C | g1 (0): A     | A, B, C | Refresh before g2 expires, C added to current gen                 |
  | 20   | D     | g3 (20): D    | g2 (10): B, C | B, C, D | Refresh after g2 expires, g1 is now stale and g2 becomes prev gen |
  | 30   | E     | g4 (30): E    | g3 (20): D    | D, E    | Refresh after g3 expires, g2 is now stale and g3 becomes prev gen |
  """
  @spec verify_token_fresh(Conn.t(), pos_integer()) :: Conn.t()
  def verify_token_fresh(conn, new_cycle_after \\ 5) do
    verify_session_payload(conn, fn conn, session ->
      current_gen_fresh_from = session.tokens_fresh_from
      prev_gen_fresh_from = session.prev_tokens_fresh_from
      now = now(conn)

      new_cycle? = current_gen_fresh_from + new_cycle_after < now
      # on a new cycle, the comparison value becomes the most recent cycle's
      fresh_from = if(new_cycle?, do: current_gen_fresh_from, else: prev_gen_fresh_from)

      conn
      |> put_private(@cycle_token_generation, new_cycle?)
      |> verify_claim("iat", fn conn, iat ->
        if iat >= fresh_from - 5, do: conn, else: "token stale"
      end)
    end)
  end

  @doc """
  Verify the session payload. The validation function `verifier` receives the conn and the session, and must return the conn or an error message.

  Must be used after `load_session/2`.

  ## Doctests / examples

      iex> verifier = fn conn, session -> if session.uid == 2, do: conn, else: "not user 2" end
      iex> conn()
      ...> |> Utils.set_session(%{uid: 1})
      ...> |> verify_session_payload(verifier)
      ...> |> Utils.get_auth_error()
      "not user 2"
  """
  @spec verify_session_payload(Conn.t(), verifier()) :: Conn.t()
  def verify_session_payload(conn, _verifier) when is_map_key(conn.private, @auth_error), do: conn

  def verify_session_payload(conn = %{private: %{@session => session}}, verifier) do
    verifier.(conn, session) |> maybe_add_error(conn)
  end

  def verify_session_payload(_, _opts), do: raise("must be used after load_session/2")

  @doc """
  Verify the bearer token payload.
  The validation function `verifier` receives the conn and the token payload, and must return the conn or an error message.

  Must be used after `verify_token_signature/2`.

  ## Doctests / examples

      iex> verifier = fn conn, payload -> is_map_key(payload, "sub") && conn || "no sub claim" end
      iex> conn()
      ...> |> Utils.set_token_payload(%{"id" => 1})
      ...> |> verify_token_payload(verifier)
      ...> |> Utils.get_auth_error()
      "no sub claim"
  """
  @compile {:inline, verify_token_payload: 2}
  @spec verify_token_payload(Conn.t(), verifier()) :: Conn.t()
  def verify_token_payload(conn, _verifier) when is_map_key(conn.private, @auth_error), do: conn

  def verify_token_payload(conn = %{private: %{@bearer_token_payload => payload}}, verifier) do
    verifier.(conn, payload) |> maybe_add_error(conn)
  end

  def verify_token_payload(_, _), do: raise("must be used after verify_token_signature/2")

  @doc """
  Verify that the bearer token payload contains `claim`, *which is assumed to be an `m::ordsets`*,
  and that `ordset` (*which is also assumed to be either an ordset or a single element*)
  is a subset of that ordset.

  > #### Ordset requirement {: .warning}
  >
  > The verified token claims **and** the comparison value **must** be properly formatted `m::ordsets`.
  > The plug does not validate this - malformed values will produce incorrect results or errors.

  Also accepts a map/keyword of claims and expected ordsets.

  ## Doctests / examples

      iex> conn()
      ...> |> Utils.set_token_payload(%{"scope" => ["a", "b", "c"]})
      ...> |> verify_token_ordset_claim_contains({"scope", "a"})
      ...> |> Utils.get_auth_error()
      nil

      iex> conn()
      ...> |> Utils.set_token_payload(%{"scope" => ["a", "b", "c"]})
      ...> |> verify_token_ordset_claim_contains(scope: ["c", "d", "e"])
      ...> |> Utils.get_auth_error()
      "bearer token claim scope does not contain [d, e]"
  """
  @spec verify_token_ordset_claim_contains(Plug.Conn.t(), claims_and_expectations()) ::
          Plug.Conn.t()
  @deprecated "It has been replaced by Charon.TokenPlugs.OrdsetClaimHas, which protects against misconfiguration by initializing comparison values as ordsets"
  def verify_token_ordset_claim_contains(conn, claims_and_ordsets) do
    verify_token_claim(conn, expectations_to_verifiers(claims_and_ordsets, &check_ordset/4))
  end

  defp check_ordset(conn, claim, claim_value, expected) do
    expected
    |> list_wrap()
    |> :ordsets.subtract(claim_value)
    |> case do
      [] -> conn
      missing -> "bearer token claim #{claim} does not contain [#{Enum.join(missing, ", ")}]"
    end
  end

  ###########
  # Private #
  ###########

  @compile {:inline, list_wrap: 1}
  defp list_wrap(list) when is_list(list), do: list
  defp list_wrap(other), do: [other]

  defp verify_claim(conn, claim, verifier) do
    verify_token_payload(conn, fn _conn, payload ->
      case payload do
        %{^claim => value} -> verifier.(conn, value)
        _ -> "bearer token claim #{claim} not found"
      end
    end)
  end

  @compile {:inline, atom_to_string: 1}
  defp atom_to_string(atom) when is_atom(atom), do: Atom.to_string(atom)
  defp atom_to_string(other), do: other

  defp expectations_to_verifiers({claim, expected}, do_verify) do
    claim = atom_to_string(claim)
    {claim, fn conn, value -> do_verify.(conn, claim, value, expected) end}
  end

  defp expectations_to_verifiers(claims_and_verifiers, do_verify) do
    for cv <- claims_and_verifiers, do: expectations_to_verifiers(cv, do_verify)
  end

  @compile {:inline, maybe_add_error: 2}
  def maybe_add_error(<<err::binary>>, conn), do: set_auth_error(conn, err)
  def maybe_add_error(conn, _conn), do: conn
end
