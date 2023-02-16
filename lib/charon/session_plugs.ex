defmodule Charon.SessionPlugs do
  @moduledoc """
  Plugs to create, update/refresh and delete sessions.
  When creating or updating a session, new tokens are created as well.
  """
  alias Plug.Conn
  require Logger
  alias Charon.{Config, Internal, TokenFactory, SessionStore}
  use Internal.Constants
  alias Charon.Models.{Session, Tokens}

  @type upsert_session_opts :: [
          access_claim_overrides: %{required(String.t()) => any()},
          refresh_claim_overrides: %{required(String.t()) => any()},
          extra_session_payload: map(),
          session_type: atom()
        ]

  @doc """
  Create or update a session. If a session exists in the conn, the session is updated / refreshed, otherwise a new one is created.
  Refresh an existing session by putting it on the connection with `Charon.TokenPlugs.load_session/2`.

  In both cases, new access / refresh tokens are created and stored in the conn's private map.
  The server-side session stored in the session store is created / updated as well.

  If a new session is created, this plug must be preceded by `Charon.Utils.set_token_signature_transport/2` and `Charon.Utils.set_user_id/2` or an error will be raised.

  The tokens' signatures are split off and sent as cookies if the session's token signature transport mechanism is set to `:cookie`. By default, these are http-only strictly-same-site secure cookies.

  Optionally, it is possible to add extra claims to the access- and refresh tokens or to store extra payload in the server-side session.

  Raises on session store errors. No recovery is possible from this error - the session HAS to be stored or there is no point in handing out tokens.

  ## Claims

  The following claims are set by default:
  - `"exp"` expires at (this value is guaranteed to never outlive the session itself)
  - `"iat"` time of token creation
  - `"iss"` issuer, usually a url like "https://myapp.com"
  - `"jti"` jwt id, random unique id for the token (a refresh token's id is stored in the session as well)
  - `"nbf"` not before, same value as `"iat"` but means "token not valid before this time"
  - `"sid"` session id
  - `"sub"` subject, the user id of the session owner
  - `"type"` type, `"access"` or `"refresh"`
  - `"styp"` session type

  Additional claims or overrides can be provided with `opts`.

  ## Examples / doctests

      # error if user id not set for new session
      iex> %Conn{} |> Utils.set_token_signature_transport(:bearer) |> upsert_session(@config)
      ** (RuntimeError) Set user id using Utils.set_user_id/2

      # error if signature transport not set for new session
      iex> %Conn{} |> Utils.set_user_id(1) |> upsert_session(@config)
      ** (RuntimeError) Set token signature transport using Utils.set_token_signature_transport/2

      # creates session if none present in conn
      iex> conn = conn()
      ...> |> Utils.set_user_id(1)
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> upsert_session(@config)
      iex> %Session{} = Utils.get_session(conn)
      iex> %Tokens{} = Utils.get_tokens(conn)

      # renews session if present in conn, updating only refresh_tokens, refreshed_at, and refresh_expires_at
      # existing session's user id will not change despite attempted override
      iex> old_session = test_session(user_id: 43, id: "a", expires_at: :infinite, refresh_expires_at: 0)
      iex> conn = conn()
      ...> |> Conn.put_private(@session, old_session)
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config)
      iex> session = Utils.get_session(conn) |> Map.from_struct()
      iex> old_session = Map.from_struct(old_session)
      iex> Enum.find(~w(id user_id created_at expires_at)a, & session[&1] != old_session[&1])
      nil
      iex> Enum.find(~w(refresh_token_id refreshed_at refresh_expires_at)a, & session[&1] == old_session[&1])
      nil

      # returns signatures in cookies if requested, which removes signatures from tokens
      iex> conn = conn()
      ...> |> Utils.set_token_signature_transport(:cookie)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config)
      iex> cookies = conn |> Conn.fetch_cookies() |> Map.get(:cookies)
      iex> <<_access_sig::binary>> = Map.get(cookies, @config.access_cookie_name)
      iex> <<_refresh_sig::binary>> = Map.get(cookies, @config.refresh_cookie_name)
      iex> true = Regex.match?(~r/\\w+\\.\\w+\\./,  conn |> Utils.get_tokens() |> Map.get(:access_token))
      iex> true = Regex.match?(~r/\\w+\\.\\w+\\./,  conn |> Utils.get_tokens() |> Map.get(:refresh_token))

      # tokens get a lot of default claims
      iex> conn = conn()
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config)
      iex> %{"exp" => _, "iat" => _, "iss" => "my_test_app", "jti" => <<_::binary>>, "nbf" => _, "sid" => <<sid::binary>>, "sub" => 1, "type" => "access", "styp" => "full"} = get_private(conn, @access_token_payload)
      iex> %{"exp" => _, "iat" => _, "iss" => "my_test_app", "jti" => <<_::binary>>, "nbf" => _, "sid" => ^sid, "sub" => 1, "type" => "refresh", "styp" => "full"} = get_private(conn, @refresh_token_payload)

      # allows adding extra claims to tokens
      iex> conn = conn()
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config, access_claim_overrides: %{"much" => :extra}, refresh_claim_overrides: %{"really" => true})
      iex> %{"much" => :extra} = get_private(conn, @access_token_payload)
      iex> %{"really" => true} = get_private(conn, @refresh_token_payload)

      # allows adding extra payload to session
      iex> conn = conn()
      ...> |> Utils.set_user_id(1)
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> upsert_session(@config, extra_session_payload: %{what?: "that's right!"})
      iex> %Session{extra_payload: %{what?: "that's right!"}} = Utils.get_session(conn)

      # allows separating sessions by type (default :full)
      iex> conn = conn()
      ...> |> Utils.set_token_signature_transport(:bearer)
      ...> |> Utils.set_user_id(1)
      ...> |> upsert_session(@config, session_type: :oauth2)
      iex> %Session{type: :oauth2} = Utils.get_session(conn)
      iex> %{"styp" => "oauth2"} = get_private(conn, @access_token_payload)
  """
  @spec upsert_session(Conn.t(), Config.t(), upsert_session_opts()) :: Conn.t()
  def upsert_session(
        conn,
        config = %{
          refresh_token_ttl: max_refresh_ttl,
          access_token_ttl: max_access_ttl,
          access_cookie_name: access_cookie_name,
          refresh_cookie_name: refresh_cookie_name,
          access_cookie_opts: access_cookie_opts,
          refresh_cookie_opts: refresh_cookie_opts,
          session_ttl: session_ttl
        },
        opts \\ []
      ) do
    now = Internal.now()
    access_claim_overrides = opts[:access_claim_overrides] || %{}
    refresh_claim_overrides = opts[:refresh_claim_overrides] || %{}
    extra_session_payload = opts[:extra_session_payload] || %{}
    session_type = opts[:session_type] || :full

    # the refresh token id is renewed every time so that refresh tokens can be single-use only
    refresh_token_id = Internal.random_url_encoded(16)

    # update the existing session or create a new one
    session =
      if existing_session = Internal.get_private(conn, @session) do
        %{
          existing_session
          | extra_payload: extra_session_payload,
            refresh_expires_at: now + max_refresh_ttl,
            refresh_token_id: refresh_token_id,
            refreshed_at: now,
            type: session_type
        }
        |> tap(&Logger.debug("REFRESHED session: #{inspect(&1)}"))
      else
        %Session{
          created_at: now,
          expires_at: if(session_ttl == :infinite, do: :infinite, else: session_ttl + now),
          extra_payload: extra_session_payload,
          id: Internal.random_url_encoded(16),
          refresh_expires_at: now + max_refresh_ttl,
          refresh_token_id: refresh_token_id,
          refreshed_at: now,
          type: session_type,
          user_id: get_user_id!(conn)
        }
        |> tap(&Logger.debug("CREATED session: #{inspect(&1)}"))
      end
      |> truncate_refresh_expires_at()

    # create access and refresh tokens and put them on the conn
    refresh_exp = session.refresh_expires_at
    refresh_ttl = refresh_exp - now
    access_ttl = min(refresh_ttl, max_access_ttl)
    access_exp = access_ttl + now

    shared_payload = %{
      "iat" => now,
      "iss" => config.token_issuer,
      "nbf" => now,
      "sid" => session.id,
      "sub" => session.user_id,
      "styp" => session.type |> Atom.to_string()
    }

    a_payload =
      shared_payload
      |> Map.merge(%{
        "jti" => Internal.random_url_encoded(16),
        "exp" => access_exp,
        "type" => "access"
      })
      |> Map.merge(access_claim_overrides)

    r_payload =
      shared_payload
      |> Map.merge(%{"jti" => refresh_token_id, "exp" => refresh_exp, "type" => "refresh"})
      |> Map.merge(refresh_claim_overrides)

    {:ok, refresh_token} = TokenFactory.sign(r_payload, config)
    {:ok, access_token} = TokenFactory.sign(a_payload, config)

    tokens = %Tokens{
      access_token: access_token,
      access_token_exp: access_exp,
      refresh_token: refresh_token,
      refresh_token_exp: refresh_exp
    }

    # store the session
    case SessionStore.upsert(session, config) do
      :ok ->
        :ok

      error ->
        error |> inspect() |> Logger.error()
        raise(RuntimeError, "session could not be stored")
    end

    # dress up the conn and return
    conn
    |> transport_tokens(
      tokens,
      access_ttl,
      refresh_ttl,
      access_cookie_opts,
      access_cookie_name,
      refresh_cookie_opts,
      refresh_cookie_name
    )
    |> Internal.put_private(%{
      @session => session,
      @access_token_payload => a_payload,
      @refresh_token_payload => r_payload
    })
  end

  @doc """
  Delete the persistent session identified by the session_id in the token claims.

  Note that the token remains valid until it expires, it is left up to the client to drop the access token. It will no longer be possible to refresh the session, however.

  ## Examples / doctests

      # instructs browsers to clear signature cookies
      iex> conn()
      ...> |> Plug.Test.put_req_cookie(@config.access_cookie_name, "anything")
      ...> |> Plug.Test.put_req_cookie(@config.refresh_cookie_name, "anything")
      ...> |> delete_session(@config)
      ...> |> Conn.fetch_cookies()
      ...> |> Map.get(:cookies)
      %{}
  """
  @spec delete_session(Conn.t(), Config.t()) :: Conn.t()
  def delete_session(
        conn,
        config = %{
          access_cookie_name: access_cookie_name,
          refresh_cookie_name: refresh_cookie_name,
          access_cookie_opts: access_cookie_opts,
          refresh_cookie_opts: refresh_cookie_opts
        }
      ) do
    case conn.private do
      %{@bearer_token_payload => %{"sub" => uid, "sid" => sid, "styp" => type}} ->
        SessionStore.delete(sid, uid, String.to_atom(type), config)

      _ ->
        :ok
    end

    conn
    |> Conn.delete_resp_cookie(refresh_cookie_name, refresh_cookie_opts)
    |> Conn.delete_resp_cookie(access_cookie_name, access_cookie_opts)
  end

  ############
  # Privates #
  ############

  defp transport_tokens(
         conn,
         tokens,
         access_ttl,
         refresh_ttl,
         access_cookie_opts,
         access_cookie_name,
         refresh_cookie_opts,
         refresh_cookie_name
       ) do
    case get_sig_transport!(conn) do
      :bearer ->
        Conn.put_private(conn, @tokens, tokens)

      :cookie ->
        split = Internal.split_signature(tokens.access_token, access_ttl, access_cookie_opts)
        {access_token, at_signature, access_cookie_opts} = split
        split = Internal.split_signature(tokens.refresh_token, refresh_ttl, refresh_cookie_opts)
        {refresh_token, rt_signature, refresh_cookie_opts} = split
        tokens = %{tokens | access_token: access_token, refresh_token: refresh_token}

        conn
        |> Conn.put_private(@tokens, tokens)
        |> Conn.put_resp_cookie(access_cookie_name, at_signature, access_cookie_opts)
        |> Conn.put_resp_cookie(refresh_cookie_name, rt_signature, refresh_cookie_opts)
    end
  end

  defp get_user_id!(conn) do
    conn
    |> Internal.get_private(@user_id)
    |> case do
      nil -> raise "Set user id using Utils.set_user_id/2"
      result -> result
    end
  end

  defp get_sig_transport!(conn) do
    conn
    |> Internal.get_private(@token_signature_transport)
    |> case do
      nil -> raise "Set token signature transport using Utils.set_token_signature_transport/2"
      result -> result
    end
  end

  defp truncate_refresh_expires_at(session)
  defp truncate_refresh_expires_at(s = %{expires_at: :infinite}), do: s

  defp truncate_refresh_expires_at(s = %{expires_at: s_exp, refresh_expires_at: rt_exp}),
    do: %{s | refresh_expires_at: min(s_exp, rt_exp)}
end
