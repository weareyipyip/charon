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
        plug :get_token_sig_from_cookie, @config.access_cookie_name
        plug :verify_token_signature, @config
        plug :verify_token_nbf_claim
        plug :verify_token_exp_claim
        plug :verify_token_claim_equals, {"type", "access"}
        plug :verify_no_auth_error, &MyApp.TokenErrorHandler.on_error/2
        plug Charon.TokenPlugs.PutAssigns
      end

  ## Refresh tokens

      defmodule MyApp.RefreshTokenPipeline do
        use Plug.Builder

        @config Charon.Config.from_enum(Application.compile_env!(:my_app, :charon))

        plug :get_token_from_auth_header
        plug :get_token_sig_from_cookie, @config.refresh_cookie_name
        plug :verify_token_signature, @config
        plug :verify_token_nbf_claim
        plug :verify_token_exp_claim
        plug :verify_token_claim_equals, {"type", "refresh"}
        plug :load_session, @config
        plug :verify_refresh_token_fresh
        plug :verify_no_auth_error, &MyApp.TokenErrorHandler.on_error/2
        plug Charon.TokenPlugs.PutAssigns
      end
  """
  alias Plug.Conn
  import Conn, except: [put_private: 3]

  alias Charon.{Config, TokenFactory, Internal, SessionStore}
  use Internal.Constants
  import Internal

  @doc """
  Get a bearer token from the `authorization` header.

  ## Doctests

      iex> conn = conn() |> put_req_header("authorization", "Bearer aaa")
      iex> conn |> get_token_from_auth_header([]) |> Utils.get_auth_error()
      nil
      iex> conn |> get_token_from_auth_header([]) |> Utils.get_token_signature_transport()
      :bearer
      iex> conn |> get_token_from_auth_header([]) |> Internal.get_private(@bearer_token)
      "aaa"

      # missing auth header
      iex> conn = conn()
      iex> conn |> get_token_from_auth_header([]) |> Utils.get_auth_error()
      "bearer token not found"

      # auth header format must be correct
      iex> conn = conn() |> put_req_header("authorization", "boom")
      iex> conn |> get_token_from_auth_header([]) |> Utils.get_auth_error()
      "bearer token not found"
      iex> conn = conn() |> put_req_header("authorization", "Bearer ")
      iex> conn |> get_token_from_auth_header([]) |> Utils.get_auth_error()
      "bearer token not found"
  """
  @spec get_token_from_auth_header(Conn.t(), any) :: Conn.t()
  def get_token_from_auth_header(conn, _opts) do
    conn
    |> get_req_header("authorization")
    |> auth_header_to_token()
    |> case do
      not_found when not_found in [nil, ""] ->
        auth_error(conn, "bearer token not found")

      token ->
        put_private(conn, %{@bearer_token => token, @token_signature_transport => :bearer})
    end
  end

  @doc """
  Appends the specified cookie's content to the bearer token, if the cookie is present and the token ends with a "." character.
  Must be used after `get_token_from_auth_header/2`.

  ## Doctests

      iex> conn = conn() |> put_private(@bearer_token, "token.") |> put_req_cookie("c", "sig") |> fetch_cookies()
      iex> conn = conn |> get_token_sig_from_cookie("c")
      iex> conn |> Utils.get_token_signature_transport()
      :cookie
      iex> conn |> Internal.get_private(@bearer_token)
      "token.sig"

      # cookie is ignored if bearer token does not end with .
      iex> conn = conn() |> put_private(@bearer_token, "token") |> put_req_cookie("c", "sig") |> fetch_cookies()
      iex> conn = conn |> get_token_sig_from_cookie("c")
      iex> conn |> Utils.get_token_signature_transport()
      nil
      iex> conn |> Internal.get_private(@bearer_token)
      "token"
  """
  @spec get_token_sig_from_cookie(Conn.t(), String.t()) :: Conn.t()
  def get_token_sig_from_cookie(conn = %{private: %{@auth_error => _}}, _), do: conn

  def get_token_sig_from_cookie(
        conn = %{private: %{@bearer_token => token}},
        cookie_name
      ) do
    with %{^cookie_name => signature} <- conn.cookies,
         true <- String.ends_with?(token, ".") do
      put_private(conn, %{
        @token_signature_transport => :cookie,
        @bearer_token => token <> signature
      })
    else
      _ -> conn
    end
  end

  def get_token_sig_from_cookie(_, _), do: raise("use after get_token_from_auth_header/2")

  @doc """
  Verify that the bearer token found by `get_token_from_auth_header/2` is signed correctly.

  ## Doctests

      iex> token = sign("hurray!")
      iex> conn = conn() |> put_private(@bearer_token, token) |> verify_token_signature(@config)
      iex> Internal.get_private(conn, @bearer_token_payload)
      "hurray!"

      # signature must match
      iex> token = sign("hurray!")
      iex> conn = conn() |> put_private(@bearer_token, token <> "boom") |> verify_token_signature(@config)
      iex> Internal.get_private(conn, @bearer_token_payload)
      nil
      iex> Utils.get_auth_error(conn)
      "bearer token signature invalid"
  """
  @spec verify_token_signature(Conn.t(), Config.t()) :: Conn.t()
  def verify_token_signature(conn = %{private: %{@auth_error => _}}, _), do: conn

  def verify_token_signature(conn = %{private: %{@bearer_token => token}}, config) do
    with {:ok, payload} <- TokenFactory.verify(token, config) do
      put_private(conn, @bearer_token_payload, payload)
    else
      _ -> auth_error(conn, "bearer token signature invalid")
    end
  end

  def verify_token_signature(_, _),
    do: raise("use after get_token_from_auth_header/2 and optionally get_token_sig_from_cookie/2")

  @doc """
  Verify that the bearer token payload contains a valid `nbf` (not before) claim.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      iex> conn = conn() |> put_private(@bearer_token_payload, %{"nbf" => Internal.now()})
      iex> ^conn = conn |> verify_token_nbf_claim([])

      # some clock drift is allowed
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"nbf" => Internal.now() + 3})
      iex> ^conn = conn |> verify_token_nbf_claim([])

      # not yet valid
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"nbf" => Internal.now() + 6})
      iex> conn |> verify_token_nbf_claim([]) |> Utils.get_auth_error()
      "bearer token not yet valid"

      # claim must be present
      iex> conn = conn() |> put_private(@bearer_token_payload, %{})
      iex> conn |> verify_token_nbf_claim([]) |> Utils.get_auth_error()
      "bearer token claim nbf not found"
  """
  @spec verify_token_nbf_claim(Conn.t(), Plug.opts()) :: Conn.t()
  def verify_token_nbf_claim(conn, _opts) do
    verify_claim(conn, "nbf", fn conn, nbf ->
      # allow some clock drift
      if now() >= nbf - 5, do: conn, else: "bearer token not yet valid"
    end)
  end

  @doc """
  Verify that the bearer token payload contains a non-expired `exp` (expires at) claim.
  Must be used after `verify_token_signature/2`.

  Note that a token created by `Charon.SessionPlugs.upsert_session/3` is guaranteed
  to have an exp claim that does not outlive its underlying session.

  ## Doctests

      iex> conn = conn() |> put_private(@bearer_token_payload, %{"exp" => Internal.now()})
      iex> ^conn = conn |> verify_token_exp_claim([])

      # some clock drift is allowed
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"exp" => Internal.now() - 3})
      iex> ^conn = conn |> verify_token_exp_claim([])

      # expired
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"exp" => Internal.now() - 6})
      iex> conn |> verify_token_exp_claim([]) |> Utils.get_auth_error()
      "bearer token expired"

      # claim must be present
      iex> conn = conn() |> put_private(@bearer_token_payload, %{})
      iex> conn |> verify_token_exp_claim([]) |> Utils.get_auth_error()
      "bearer token claim exp not found"
  """
  @spec verify_token_exp_claim(Conn.t(), Plug.opts()) :: Conn.t()
  def verify_token_exp_claim(conn, _opts) do
    verify_claim(conn, "exp", fn conn, exp ->
      # allow some clock drift
      if now() < exp + 5, do: conn, else: "bearer token expired"
    end)
  end

  @doc """
  Verify that the bearer token payload contains `claim` and that its value is in `expected`.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      iex> conn = conn() |> put_private(@bearer_token_payload, %{"type" => "access"})
      iex> ^conn = conn |> verify_token_claim_in({"type", ~w(access)})

      # invalid
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"type" => "refresh"})
      iex> conn |> verify_token_claim_in({"type", ~w(access)}) |> Utils.get_auth_error()
      "bearer token claim type invalid"

      # claim must be present
      iex> conn = conn() |> put_private(@bearer_token_payload, %{})
      iex> conn |> verify_token_claim_in({"type", ~w(access)}) |> Utils.get_auth_error()
      "bearer token claim type not found"
  """
  @spec verify_token_claim_in(Conn.t(), {String.t(), [String.t()]}) :: Conn.t()
  def verify_token_claim_in(conn, _claim_and_expected = {claim, expected}) do
    verify_claim(conn, claim, fn conn, v ->
      if v in expected, do: conn, else: "bearer token claim #{claim} invalid"
    end)
  end

  @doc """
  Verify that the bearer token payload contains `claim` and that its value is `expected`.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      iex> conn = conn() |> put_private(@bearer_token_payload, %{"type" => "access"})
      iex> ^conn = conn |> verify_token_claim_equals({"type", "access"})

      # invalid
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"type" => "refresh"})
      iex> conn |> verify_token_claim_equals({"type", "access"}) |> Utils.get_auth_error()
      "bearer token claim type invalid"

      # claim must be present
      iex> conn = conn() |> put_private(@bearer_token_payload, %{})
      iex> conn |> verify_token_claim_equals({"type", "access"}) |> Utils.get_auth_error()
      "bearer token claim type not found"
  """
  @spec verify_token_claim_equals(Conn.t(), {String.t(), String.t()}) :: Conn.t()
  def verify_token_claim_equals(conn, _claim_and_expected = {claim, expected}),
    do: verify_token_claim_in(conn, {claim, [expected]})

  @doc """
  Generically verify that the bearer token payload contains `claim` and that its value matches `func`. The function must return the conn or an error message.
  Must be used after `verify_token_signature/2`.

  ## Doctests

      def verify_read_scope(conn, value) do
        if "read" in String.split(value, ",") do
          conn
        else
          "no read scope"
        end
      end

      iex> conn = conn() |> put_private(@bearer_token_payload, %{"scope" => "read,write"})
      iex> ^conn = conn |> verify_token_claim({"scope", &verify_read_scope/2})

      # invalid
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"scope" => "write"})
      iex> conn |> verify_token_claim({"scope", &verify_read_scope/2}) |> Utils.get_auth_error()
      "no read scope"

      # claim must be present
      iex> conn = conn() |> put_private(@bearer_token_payload, %{})
      iex> conn |> verify_token_claim({"scope", &verify_read_scope/2}) |> Utils.get_auth_error()
      "bearer token claim scope not found"
  """
  @spec verify_token_claim(Conn.t(), {String.t(), (Conn.t(), any() -> Conn.t() | binary())}) ::
          Conn.t()
  def verify_token_claim(conn, _claim_and_verifier = {claim, func}),
    do: verify_claim(conn, claim, func)

  @doc """
  Make sure that no previous plug of this module added an auth error.
  In case of an error, `on_error` is called (it must halt the connection!).

  ## Doctests

      iex> conn = conn()
      iex> ^conn = verify_no_auth_error(conn, fn _conn, _error -> "BOOM" end)

      # on error, send an error response
      iex> conn = conn() |> Internal.auth_error("oops!")
      iex> conn = verify_no_auth_error(conn, & &1 |> send_resp(401, &2) |> halt())
      iex> conn.halted
      true
      iex> conn.resp_body
      "oops!"
  """
  @spec verify_no_auth_error(Plug.Conn.t(), (Conn.t(), [String.t()] -> Conn.t())) ::
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

      iex> command(["SET", session_key("a", 1), test_session() |> Session.serialize()])
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"sid" => "a", "sub" => 1})
      iex> %Session{} = conn |> load_session(@config) |> Internal.get_private(@session)

      # token payload must contain "sub" and "sid" claims
      iex> conn = conn() |> put_private(@bearer_token_payload, 1)
      iex> conn |> load_session(@config) |> Utils.get_auth_error()
      "bearer token claim sub or sid not found"

      # session must be found
      iex> conn = conn() |> put_private(@bearer_token_payload, %{"sid" => "a", "sub" => 1})
      iex> conn |> load_session(@config) |> Utils.get_auth_error()
      "session not found"
  """
  @spec load_session(Conn.t(), Config.t()) :: Conn.t()
  def load_session(conn = %{private: %{@auth_error => _}}, _), do: conn

  def load_session(conn = %{private: %{@bearer_token_payload => payload}}, config) do
    with %{"sub" => uid, "sid" => sid} <- payload,
         session = %{} <- SessionStore.get(sid, uid, config) do
      put_private(conn, @session, session)
    else
      nil -> auth_error(conn, "session not found")
      {:error, error} -> raise "could not fetch session: #{inspect(error)}"
      _error -> auth_error(conn, "bearer token claim sub or sid not found")
    end
  end

  def load_session(_, _), do: raise("must be used after verify_token_signature/2")

  @doc """
  Verify that the refresh token has not been used yet (= that it matches the token id stored in the session).
  Must be used after `load_session/2`. Verify the token type with `verify_token_claim_equals/2`.

  ## Doctests

      iex> conn = conn() |> put_private(@session, %{refresh_token_id: "a"}) |> put_private(@bearer_token_payload, %{"jti" => "a"})
      iex> ^conn = conn |> verify_refresh_token_fresh([])

      # token's jti claim does not match session's refresh_token_id
      iex> conn = conn() |> put_private(@session, %{refresh_token_id: "a"}) |> put_private(@bearer_token_payload, %{"jti" => "b"})
      iex> conn |> verify_refresh_token_fresh([]) |> Utils.get_auth_error()
      "refresh token stale"

      # token's jti claim missing
      iex> conn = conn() |> put_private(@session, %{refresh_token_id: "a"}) |> put_private(@bearer_token_payload, %{})
      iex> conn |> verify_refresh_token_fresh([]) |> Utils.get_auth_error()
      "bearer token claim jti not found"
  """
  @spec verify_refresh_token_fresh(Conn.t(), Plug.opts()) :: Conn.t()
  def verify_refresh_token_fresh(conn = %{private: %{@auth_error => _}}, _opts), do: conn

  def verify_refresh_token_fresh(
        conn = %{private: %{@session => %{refresh_token_id: expected}}},
        _opts
      ) do
    verify_claim(conn, "jti", fn
      conn, ^expected -> conn
      _, _ -> "refresh token stale"
    end)
  end

  def verify_refresh_token_fresh(_, _opts), do: raise("must be used after load_session/2")

  ###########
  # Private #
  ###########

  defp auth_header_to_token(["Bearer " <> token | _]), do: token
  defp auth_header_to_token(["Bearer: " <> token | _]), do: token
  defp auth_header_to_token(_), do: nil

  defp verify_claim(conn = %{private: %{@auth_error => _}}, _, _), do: conn

  defp verify_claim(conn = %{private: %{@bearer_token_payload => payload}}, claim, func) do
    with %{^claim => value} <- payload do
      func.(conn, value)
    else
      _ -> "bearer token claim #{claim} not found"
    end
    |> case do
      <<error::binary>> -> auth_error(conn, error)
      conn -> conn
    end
  end

  defp verify_claim(_, _, _), do: raise("must be used after verify_token_signature/2")
end
