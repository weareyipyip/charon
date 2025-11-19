defmodule Charon.SessionPlugs do
  @moduledoc """
  Plugs to create, update/refresh and delete sessions.
  When creating or updating a session, new tokens are created as well.
  """
  alias Plug.Conn
  require Logger
  alias Charon.{Config, Internal, TokenFactory, SessionStore, Models}
  use Internal.Constants
  import Internal.Crypto
  alias Models.{Session, Tokens}
  alias __MODULE__.{SessionStorageError, SessionUpdateConflictError, InsecureTokenTransportError}

  @type upsert_session_opts :: [
          user_id: any(),
          token_transport: binary() | :cookie | :bearer | :cookie_only,
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

  If a new session is created, options `:user_id` and `:token_transport` must be provided or an error will be raised.

  The token transport can be:
   - `:cookie_only` - *full* tokens are returned to the client as cookies
   - `:cookie` - *partial* tokens are returned to the client as cookies (only the tokens' signature, the rest should be sent in the response body)
   - `:bearer` - no cookies are sent to the client, the tokens should be sent in the response body

  Please read up on CSRF protection in [README](README.md#csrf-protection) when using cookies. The slightly awkward naming of `:cookie` and `:cookie_only` exists for legacy reasons and is kept for backwards compatibility.

  If config option `:enforce_browser_cookies` is enabled, browser clients will be attempted to be
  detected by the presence of (forbidden) header "Sec-Fetch-Mode", in which case only cookie-based
  token transports will be allowed.

  Optionally, it is possible to add extra claims to the access- and refresh tokens or to store extra payload in the server-side session.

  Session stores may return an optimistic locking error, meaning there are concurrent updates to a session.
  In this case, `upsert/3` will raise a `Charon.SessionPlugs.SessionUpdateConflictError`, which should result
  in an HTTP 409 Conflict error.
  If the session store returns another error, a `Charon.SessionPlugs.SessionStorageError` is raised,
  which is an unrecoverable state that should result in an HTTP 500 Internal Server Error.

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

  ## Options:

  - `:user_id` (required when creating a new session) - The user ID for the session owner
  - `:token_transport` (required when creating a new session) - How tokens are transported to the client
  - `:access_claim_overrides` - Map of additional or overridden claims for the access token
  - `:refresh_claim_overrides` - Map of additional or overridden claims for the refresh token
  - `:extra_session_payload` - Map of additional data to store in the server-side session
  - `:session_type` - Session type atom (defaults to `:full`). Used to categorize sessions that require different lifecycle management. For example, OAuth2 provider sessions (see [CharonOauth2](`e:charon_oauth2:readme.html`)) or API key sessions might use a distinct type to ensure they are excluded from bulk operations like "logout all sessions". Only needed for specialized use cases.

  ## Examples

  Create a new session for a user:

      iex> conn = upsert_session(conn(), @config, user_id: 1, token_transport: :bearer)
      iex> %Session{} = Utils.get_session(conn)
      iex> %Tokens{} = Utils.get_tokens(conn)

  Create a session with infinite lifespan:

      iex> conn = upsert_session(conn(), %{@config | session_ttl: :infinite}, user_id: 1, token_transport: :bearer)
      iex> %Session{expires_at: :infinite} = Utils.get_session(conn)

  Add extra payload to the session:

      iex> conn = upsert_session(
      ...>   conn(),
      ...>   @config,
      ...>   user_id: 1,
      ...>   token_transport: :bearer,
      ...>   extra_session_payload: %{role: :admin}
      ...> )
      iex> %Session{extra_payload: %{role: :admin}} = Utils.get_session(conn)
  """
  @spec upsert_session(Conn.t(), Config.t(), upsert_session_opts()) :: Conn.t()
  def upsert_session(conn, config, opts \\ []) do
    token_transport = get_token_transport!(conn, config, opts)
    existing_session = Internal.get_private(conn, @session)
    timestamps = conn |> Internal.now() |> calc_timestamps(existing_session, config)

    new_session = create_or_update_session(conn, existing_session, timestamps, config, opts)
    new_session |> SessionStore.upsert(config) |> raise_on_store_error()

    {access_tok_pl, refresh_tok_pl} = create_token_payloads(new_session, timestamps, config, opts)
    tokens = create_tokens(access_tok_pl, refresh_tok_pl, timestamps, config)

    conn
    |> maybe_set_cookies(tokens, timestamps, config, token_transport)
    |> Internal.put_private(%{
      @session => new_session,
      @access_token_payload => access_tok_pl,
      @refresh_token_payload => refresh_tok_pl
    })
  end

  @doc """
  Delete the persistent session identified by the session_id in the token claims.

  Note that the token remains valid until it expires, it is left up to the client to drop the access token. It will no longer be possible to refresh the session, however.

  This function also instructs browsers to clear signature cookies.
  """
  @spec delete_session(Conn.t(), Config.t()) :: Conn.t()
  def delete_session(conn, config) do
    case conn do
      %{private: %{@bearer_token_payload => %{"sub" => uid, "sid" => sid, "styp" => type}}} ->
        SessionStore.delete(sid, uid, String.to_atom(type), config) |> raise_on_store_error()

      _ ->
        :ok
    end

    conn
    |> Conn.delete_resp_cookie(config.refresh_cookie_name, config.refresh_cookie_opts)
    |> Conn.delete_resp_cookie(config.access_cookie_name, config.access_cookie_opts)
  end

  ###########
  # Private #
  ###########

  defp calc_timestamps(now, existing_session, config) do
    {session_exp, session_ttl} = calc_session_exp_ttl(existing_session, config.session_ttl, now)
    # atom > int so this works if session_ttl is :infinite
    refresh_ttl = min(config.refresh_token_ttl, session_ttl)
    access_ttl = min(config.access_token_ttl, refresh_ttl)
    refresh_exp = refresh_ttl + now
    access_exp = access_ttl + now
    {now, session_exp, refresh_exp, access_exp, refresh_ttl, access_ttl}
  end

  defp calc_session_exp_ttl(existing_session, new_session_ttl, now)
  defp calc_session_exp_ttl(nil, :infinite, _), do: {:infinite, :infinite}
  defp calc_session_exp_ttl(nil, ttl, now), do: {ttl + now, ttl}
  defp calc_session_exp_ttl(%{expires_at: :infinite}, _, _), do: {:infinite, :infinite}
  defp calc_session_exp_ttl(%{expires_at: exp}, _, now), do: {exp, exp - now}

  defp create_or_update_session(conn, session, timestamps, config, opts) do
    {now, session_exp, refresh_exp, _, _, _} = timestamps
    refresh_token_id = gen_id(config)
    extra_session_payload = opts[:extra_session_payload] || %{}

    if session do
      %{
        session
        | extra_payload: extra_session_payload,
          refresh_expires_at: refresh_exp,
          refresh_token_id: refresh_token_id,
          refreshed_at: now
      }
      |> maybe_cycle_token_generation(conn, now)
      |> on_upsert("REFRESHED")
    else
      %Session{
        created_at: now,
        expires_at: session_exp,
        extra_payload: extra_session_payload,
        id: gen_id(config),
        prev_tokens_fresh_from: now,
        refresh_expires_at: refresh_exp,
        refresh_token_id: refresh_token_id,
        refreshed_at: now,
        tokens_fresh_from: now,
        type: opts[:session_type] || :full,
        user_id: get_user_id!(conn, opts)
      }
      |> on_upsert("CREATED")
    end
  end

  defp on_upsert(session, event) do
    Logger.debug("#{event} session: #{inspect(session)}")
    session
  end

  defp maybe_cycle_token_generation(session, %{private: %{@cycle_token_generation => true}}, now) do
    %{session | tokens_fresh_from: now, prev_tokens_fresh_from: session.tokens_fresh_from}
  end

  defp maybe_cycle_token_generation(session, _conn, _now), do: session

  defp get_user_id!(conn, opts) do
    (Internal.get_private(conn, @user_id) || opts[:user_id])
    |> case do
      nil -> raise "Set user id using upsert_session/3 option :user_id"
      result -> result
    end
  end

  defp raise_on_store_error(:ok), do: :ok
  defp raise_on_store_error({:error, :conflict}), do: raise(SessionUpdateConflictError)

  defp raise_on_store_error(error) do
    raise SessionStorageError, error: error
  end

  defp create_token_payloads(session, {now, _, refresh_exp, access_exp, _, _}, config, opts) do
    shared_payload = %{
      "iat" => now,
      "iss" => config.token_issuer,
      "nbf" => now,
      "sid" => session.id,
      "sub" => session.user_id,
      "styp" => session.type |> Atom.to_string()
    }

    access_token_payload =
      shared_payload
      |> Map.merge(%{"jti" => gen_id(config), "exp" => access_exp, "type" => "access"})
      |> Map.merge(opts[:access_claim_overrides] || %{})

    refresh_token_payload =
      shared_payload
      |> Map.merge(%{
        "jti" => session.refresh_token_id,
        "exp" => refresh_exp,
        "type" => "refresh"
      })
      |> Map.merge(opts[:refresh_claim_overrides] || %{})

    {access_token_payload, refresh_token_payload}
  end

  defp create_tokens(access_tok_pl, refresh_tok_pl, {_, _, refresh_exp, access_exp, _, _}, config) do
    {:ok, refresh_token} = TokenFactory.sign(refresh_tok_pl, config)
    {:ok, access_token} = TokenFactory.sign(access_tok_pl, config)

    %Tokens{
      access_token: access_token,
      access_token_exp: access_exp,
      refresh_token: refresh_token,
      refresh_token_exp: refresh_exp
    }
  end

  defp maybe_set_cookies(conn, tokens, _, _, :bearer), do: Conn.put_private(conn, @tokens, tokens)

  defp maybe_set_cookies(conn, tokens, {_, _, _, _, refresh_ttl, access_ttl}, config, transport) do
    %{access_token: access_token, refresh_token: refresh_token} = tokens

    {{access_token, access_cookie}, {refresh_token, refresh_cookie}} =
      case transport do
        :cookie -> {split_signature(access_token), split_signature(refresh_token)}
        :cookie_only -> {{nil, access_token}, {nil, refresh_token}}
      end

    tokens = %{tokens | access_token: access_token, refresh_token: refresh_token}
    access_opts = create_cookie_opts(config.access_cookie_opts, access_ttl)
    refresh_opts = create_cookie_opts(config.refresh_cookie_opts, refresh_ttl)

    conn
    |> Conn.put_private(@tokens, tokens)
    |> Conn.put_resp_cookie(config.access_cookie_name, access_cookie, access_opts)
    |> Conn.put_resp_cookie(config.refresh_cookie_name, refresh_cookie, refresh_opts)
  end

  defp get_token_transport!(conn, config, opts) do
    (Internal.get_private(conn, @token_transport) || opts[:token_transport])
    |> case do
      nil ->
        raise "Set token transport using upsert_session/3 option :token_transport"

      result ->
        result |> Internal.parse_token_transport() |> require_cookie_for_browser(conn, config)
    end
  end

  defp create_cookie_opts(cookie_opts, ttl) do
    [http_only: true, same_site: "Strict", secure: true, max_age: ttl]
    |> Keyword.merge(cookie_opts)
  end

  defp split_signature(token) do
    [header, payload, signature] = Internal.dot_split(token, parts: 3)
    {"#{header}.#{payload}", ".#{signature}"}
  end

  defp gen_id(config)
  defp gen_id(%{gen_id: :random}), do: random_url_encoded(16)
  defp gen_id(%{gen_id: fun}), do: fun.()

  defp require_cookie_for_browser(transport, conn, config) do
    if transport == :bearer and config.enforce_browser_cookies and
         Conn.get_req_header(conn, "sec-fetch-mode") != [],
       do: raise(InsecureTokenTransportError)

    transport
  end
end
