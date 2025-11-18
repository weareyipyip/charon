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
        plug :verify_token_claim_equals, {"type", "access"}
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
        plug :verify_token_claim_equals, {"type", "refresh"}
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

  @doc """
  Get a bearer token from the `authorization` header.

  ## Doctests

      iex> conn = conn() |> put_req_header("authorization", "Bearer aaa") |> get_token_from_auth_header([])
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {"aaa", :bearer}

      # missing auth header
      iex> conn = conn() |> get_token_from_auth_header([])
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {nil, nil}

      # auth header format must be correct
      iex> conn = conn() |> put_req_header("authorization", "boom") |> get_token_from_auth_header([])
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {nil, nil}
      iex> conn = conn() |> put_req_header("authorization", "Bearer ") |> get_token_from_auth_header([])
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {nil, nil}
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

  ## Doctests

      # if no cookie is set the bearer token is left unchanged
      iex> conn = conn() |> put_req_header("authorization", "Bearer token") |> get_token_from_auth_header([]) |> fetch_cookies() |> get_token_from_cookie("c")
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {"token", :bearer}

      # cookie contents are used as token if no bearer token was found previously
      iex> conn = conn() |> put_req_cookie("c", "cookie token") |> fetch_cookies() |> get_token_from_cookie("c")
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {"cookie token", :cookie_only}

      # the bearer token and cookie are concatenated if they respectively end in or start with a dot
      iex> conn = conn() |> put_req_header("authorization", "Bearer token") |> get_token_from_auth_header([]) |> put_req_cookie("c", ".sig") |> fetch_cookies() |> get_token_from_cookie("c")
      iex> {Utils.get_bearer_token(conn), Utils.get_token_transport(conn)}
      {"token.sig", :cookie}
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
  Verify that the bearer token found by `get_token_from_auth_header/2` is signed correctly.

  ## Doctests

      iex> token = sign(%{"msg" => "hurray!"})
      iex> conn = conn() |> set_token(token) |> verify_token_signature(@config)
      iex> %{"msg" => "hurray!"} = Internal.get_private(conn, @bearer_token_payload)

      # signature must match
      iex> token = sign(%{"msg" => "hurray!"})
      iex> conn = conn() |> set_token(token <> "boom") |> verify_token_signature(@config)
      iex> Internal.get_private(conn, @bearer_token_payload)
      nil
      iex> Utils.get_auth_error(conn)
      "bearer token signature invalid"

      iex> conn() |> verify_token_signature(@config) |> Utils.get_auth_error()
      "bearer token not found"
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

  ## Doctests

      iex> conn = conn() |> set_token_payload(%{"nbf" => Internal.now()})
      iex> ^conn = conn |> verify_token_nbf_claim([])

      # some clock drift is allowed
      iex> conn = conn() |> set_token_payload(%{"nbf" => Internal.now() + 3})
      iex> ^conn = conn |> verify_token_nbf_claim([])

      # not yet valid
      iex> conn = conn() |> set_token_payload(%{"nbf" => Internal.now() + 6})
      iex> conn |> verify_token_nbf_claim([]) |> Utils.get_auth_error()
      "bearer token not yet valid"

      # claim must be present
      iex> conn = conn() |> set_token_payload(%{})
      iex> conn |> verify_token_nbf_claim([]) |> Utils.get_auth_error()
      "bearer token claim nbf not found"
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

  ## Doctests

      iex> conn = conn() |> set_token_payload(%{"exp" => Internal.now()})
      iex> ^conn = conn |> verify_token_exp_claim([])

      # some clock drift is allowed
      iex> conn = conn() |> set_token_payload(%{"exp" => Internal.now() - 3})
      iex> ^conn = conn |> verify_token_exp_claim([])

      # expired
      iex> conn = conn() |> set_token_payload(%{"exp" => Internal.now() - 6})
      iex> conn |> verify_token_exp_claim([]) |> Utils.get_auth_error()
      "bearer token expired"

      # claim must be present
      iex> conn = conn() |> set_token_payload(%{})
      iex> conn |> verify_token_exp_claim([]) |> Utils.get_auth_error()
      "bearer token claim exp not found"
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
  Must be used after `verify_token_signature/2`.

  ## Doctests

      iex> conn = conn() |> set_token_payload(%{"type" => "access"})
      iex> ^conn = conn |> verify_token_claim_in({"type", ~w(access)})

      # invalid
      iex> conn = conn() |> set_token_payload(%{"type" => "refresh"})
      iex> conn |> verify_token_claim_in({"type", ~w(access)}) |> Utils.get_auth_error()
      "bearer token claim type invalid"

      # claim must be present
      iex> conn = conn() |> set_token_payload(%{})
      iex> conn |> verify_token_claim_in({"type", ~w(access)}) |> Utils.get_auth_error()
      "bearer token claim type not found"
  """
  @spec verify_token_claim_in(Conn.t(), {String.t(), [any()]}) :: Conn.t()
  def verify_token_claim_in(conn, _claim_and_expected = {claim, expected}) do
    verify_claim(conn, claim, fn conn, v ->
      if v in expected, do: conn, else: "bearer token claim #{claim} invalid"
    end)
  end

  @doc """
  Verify that the bearer token payload contains `claim` and that its value is `expected`.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      iex> conn = conn() |> set_token_payload(%{"type" => "access"})
      iex> ^conn = conn |> verify_token_claim_equals({"type", "access"})

      # invalid
      iex> conn = conn() |> set_token_payload(%{"type" => "refresh"})
      iex> conn |> verify_token_claim_equals({"type", "access"}) |> Utils.get_auth_error()
      "bearer token claim type invalid"

      # claim must be present
      iex> conn = conn() |> set_token_payload(%{})
      iex> conn |> verify_token_claim_equals({"type", "access"}) |> Utils.get_auth_error()
      "bearer token claim type not found"
  """
  @spec verify_token_claim_equals(Conn.t(), {String.t(), String.t()}) :: Conn.t()
  def verify_token_claim_equals(conn, _claim_and_expected = {claim, expected}),
    do: verify_token_claim_in(conn, {claim, [expected]})

  @doc """
  Verify that the bearer token payload contains `claim` and that its value matches `verifier`. The function must return the conn or an error message.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      def verify_read_scope(conn, value) do
        if "read" in String.split(value, ",") do
          conn
        else
          "no read scope"
        end
      end

      iex> conn = conn() |> set_token_payload(%{"scope" => "read,write"})
      iex> ^conn = conn |> verify_token_claim({"scope", &verify_read_scope/2})

      # invalid
      iex> conn = conn() |> set_token_payload(%{"scope" => "write"})
      iex> conn |> verify_token_claim({"scope", &verify_read_scope/2}) |> Utils.get_auth_error()
      "no read scope"

      # claim must be present
      iex> conn = conn() |> set_token_payload(%{})
      iex> conn |> verify_token_claim({"scope", &verify_read_scope/2}) |> Utils.get_auth_error()
      "bearer token claim scope not found"
  """
  @spec verify_token_claim(Conn.t(), {String.t(), (Conn.t(), any() -> Conn.t() | binary())}) ::
          Conn.t()
  def verify_token_claim(conn, _claim_and_verifier = {claim, verifier}),
    do: verify_claim(conn, claim, verifier)

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

  ## Doctests

      iex> conn = conn()
      iex> ^conn = verify_no_auth_error(conn, fn _conn, _error -> "BOOM" end)

      # on error, send an error response
      iex> conn = conn() |> set_auth_error("oops!")
      iex> conn = verify_no_auth_error(conn, & &1 |> send_resp(401, &2) |> halt())
      iex> conn.halted
      true
      iex> conn.resp_body
      "oops!"
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

  ## Doctests

      iex> SessionStore.upsert(test_session(refresh_expires_at: 999999999999999), @config)
      iex> conn = conn() |> set_token_payload(%{"sid" => "a", "sub" => 1, "styp" => "full"})
      iex> %Session{} = conn |> load_session(@config) |> Internal.get_private(@session)

      # token payload must contain "sub", "sid" and "styp" claims
      iex> conn = conn() |> set_token_payload(1)
      iex> conn |> load_session(@config) |> Utils.get_auth_error()
      "bearer token claim sub, sid or styp not found"

      # session must be found
      iex> conn = conn() |> set_token_payload(%{"sid" => "a", "sub" => 1, "styp" => "full"})
      iex> conn |> load_session(@config) |> Utils.get_auth_error()
      "session not found"

      iex> conn() |> load_session(@config)
      ** (RuntimeError) must be used after verify_token_signature/2
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

  ## Doctests

      # some clock drift is allowed
      iex> now = Internal.now()
      iex> conn = conn() |> set_session(%{tokens_fresh_from: now, prev_tokens_fresh_from: now - 10}) |> set_token_payload(%{"iat" => now - 11})
      iex> conn |> verify_token_fresh(5) |> Utils.get_auth_error()
      nil

      # if current gen is still within the cycle TTL, tokens from both it and previous gen are "fresh"
      iex> now = Internal.now()
      iex> conn = conn() |> set_session(%{tokens_fresh_from: now - 3, prev_tokens_fresh_from: now - 10})
      iex> conn |> set_token_payload(%{"iat" => now}) |> verify_token_fresh(5) |> Utils.get_auth_error()
      nil
      # tokens are invalid from: iat < now - 10 (*previous* gen age) - 5 (max clock drift)
      # younger-than-previous-gen-plus-clock-drift token is valid
      iex> conn |> set_token_payload(%{"iat" => now - 15}) |> verify_token_fresh(5) |> Utils.get_auth_error()
      nil
      # older-than-previous-gen-plus-clock-drift token is invalid
      iex> conn |> set_token_payload(%{"iat" => now - 16}) |> verify_token_fresh(5) |> Utils.get_auth_error()
      "token stale"
      # no generation cycle will take place
      iex> conn |> set_token_payload(%{"iat" => now}) |> verify_token_fresh(5) |> Internal.get_private(@cycle_token_generation)
      false

      # if current gen is too old, a generation cycle happens, and previous gen tokens are no longer valid
      # tokens are invalid from: iat < now - 10 (*current* gen age) - 5 (max clock drift)
      iex> now = Internal.now()
      iex> conn = conn() |> set_session(%{tokens_fresh_from: now - 10, prev_tokens_fresh_from: now - 20})
      iex> conn |> set_token_payload(%{"iat" => now}) |> verify_token_fresh(5) |> Utils.get_auth_error()
      nil
      # younger-than-current-gen-plus-clock-drift token is valid
      iex> conn |> set_token_payload(%{"iat" => now - 15}) |> verify_token_fresh(5) |> Utils.get_auth_error()
      nil
      # older-than-current-gen-plus-clock-drift token is invalid
      iex> conn |> set_token_payload(%{"iat" => now - 16}) |> verify_token_fresh(5) |> Utils.get_auth_error()
      "token stale"
      # a generation cycle will occur
      iex> conn |> set_token_payload(%{"iat" => now}) |> verify_token_fresh(5) |> Internal.get_private(@cycle_token_generation)
      true

      # claim must be present
      iex> conn = conn() |> set_session(%{tokens_fresh_from: 0, prev_tokens_fresh_from: 0}) |> set_token_payload(%{})
      iex> conn |> verify_token_fresh(5) |> Utils.get_auth_error()
      "bearer token claim iat not found"
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
  Verify the session payload.
  The validation function `verifier` must return the conn or an error message.
  Must be used after `load_session/2`.

  ## Doctests

      iex> conn = conn() |> set_session(%{the: "session"})
      iex> ^conn = conn |> verify_session_payload(fn conn, %{the: "session"} -> conn end)

      # invalid
      iex> conn = conn() |> set_session(%{the: "session"})
      iex> conn |> verify_session_payload(fn _conn, s -> s[:missing] || "invalid" end) |> Utils.get_auth_error()
      "invalid"

      iex> conn() |> verify_session_payload(fn conn, _ -> conn end)
      ** (RuntimeError) must be used after load_session/2
  """
  @spec verify_session_payload(Conn.t(), (Conn.t(), any -> Conn.t() | binary())) :: Conn.t()
  def verify_session_payload(conn, _verifier) when is_map_key(conn.private, @auth_error), do: conn

  def verify_session_payload(conn = %{private: %{@session => session}}, verifier) do
    verifier.(conn, session) |> maybe_add_error(conn)
  end

  def verify_session_payload(_, _opts), do: raise("must be used after load_session/2")

  @doc """
  Verify the bearer token payload.
  The validation function `verifier` must return the conn or an error message.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      iex> conn = conn() |> set_token_payload(%{})
      iex> ^conn = conn |> verify_token_payload(fn conn, _pl -> conn end)

      # invalid
      iex> conn = conn() |> set_token_payload(%{"scope" => "write"})
      iex> conn |> verify_token_payload(fn _conn, _pl -> "no read scope" end) |> Utils.get_auth_error()
      "no read scope"

      iex> conn() |> verify_token_payload(fn conn, _pl -> conn end)
      ** (RuntimeError) must be used after verify_token_signature/2
  """
  @compile {:inline, verify_token_payload: 2}
  @spec verify_token_payload(Conn.t(), (Conn.t(), any -> Conn.t() | binary())) :: Conn.t()
  def verify_token_payload(conn, _verifier) when is_map_key(conn.private, @auth_error), do: conn

  def verify_token_payload(conn = %{private: %{@bearer_token_payload => payload}}, verifier) do
    verifier.(conn, payload) |> maybe_add_error(conn)
  end

  def verify_token_payload(_, _), do: raise("must be used after verify_token_signature/2")

  @doc """
  Verify that the bearer token payload contains `claim`, *which is assumed to be an `m::ordsets`*,
  and that `ordset` (*which is also assumed to be either an ordset or a single element*)
   is a subset of that ordset.

  ## Doctests

      iex> conn = conn() |> set_token_payload(%{"scope" => ~w(a b c)})
      iex> ^conn = conn |> verify_token_ordset_claim_contains({"scope", "a"})
      iex> ^conn = conn |> verify_token_ordset_claim_contains({"scope", ~w(a b)})

      # invalid
      iex> conn = conn() |> set_token_payload(%{"scope" => ~w(a b c)})
      iex> conn |> verify_token_ordset_claim_contains({"scope", "d"}) |> get_auth_error()
      "bearer token claim scope does not contain [d]"
      iex> conn |> verify_token_ordset_claim_contains({"scope", ~w(d e)}) |> get_auth_error()
      "bearer token claim scope does not contain [d, e]"

      # claim must be present
      iex> conn = conn() |> set_token_payload(%{})
      iex> conn |> verify_token_ordset_claim_contains({"scope", ~w(a b c)}) |> get_auth_error()
      "bearer token claim scope not found"

      # WATCH OUT!
      # things will go horribly wrong if either the claim or the comparison value is not an ordset
      iex> conn = conn() |> set_token_payload(%{"scope" => ~w(c b a)})
      iex> conn |> verify_token_ordset_claim_contains({"scope", "a"}) |> get_auth_error()
      "bearer token claim scope does not contain [a]"
      iex> conn = conn() |> set_token_payload(%{"scope" => ~w(a b c)})
      iex> conn |> verify_token_ordset_claim_contains({"scope", ~w(b a)}) |> get_auth_error()
      "bearer token claim scope does not contain [a]"
  """
  @spec verify_token_ordset_claim_contains(Plug.Conn.t(), {binary, any}) :: Plug.Conn.t()
  def verify_token_ordset_claim_contains(conn, _claim_and_ordset = {claim, element_or_ordset}) do
    verifier = fn conn, claim_value ->
      element_or_ordset
      |> List.wrap()
      |> :ordsets.subtract(claim_value)
      |> case do
        [] -> conn
        missing -> "bearer token claim #{claim} does not contain [#{Enum.join(missing, ", ")}]"
      end
    end

    verify_claim(conn, claim, verifier)
  end

  ###########
  # Private #
  ###########

  defp verify_claim(conn, claim, verifier) do
    verify_token_payload(conn, fn _conn, payload ->
      case payload do
        %{^claim => value} -> verifier.(conn, value)
        _ -> "bearer token claim #{claim} not found"
      end
    end)
  end

  defp maybe_add_error(<<err::binary>>, conn), do: set_auth_error(conn, err)
  defp maybe_add_error(conn, _conn), do: conn
end
