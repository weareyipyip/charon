defmodule Charon.TestHelpers do
  @moduledoc """
  Utility functions for writing tests.
  """
  alias Plug.Conn
  alias Charon.{Config, Utils, SessionPlugs, Models}
  alias Models.{Session, Tokens}
  use Charon.Internal.Constants

  @type test_session :: %{session: Session.t(), tokens: Tokens.t(), cookies: Conn.resp_cookies()}

  @doc """
  Override configuration for an optional module.
  """
  @spec override_opt_mod_conf(Config.t(), atom | binary(), map | keyword()) ::
          Config.t()
  def override_opt_mod_conf(config, module, overrides) do
    opt_mods = config.optional_modules
    mod_conf = opt_mods |> Map.get(module, %{}) |> Map.merge(Map.new(overrides))
    opt_mods = Map.merge(opt_mods, %{module => mod_conf})
    %{config | optional_modules: opt_mods}
  end

  @doc """
  Create a test session and return the session, a set of tokens for it and the response cookies.

  ## Options

    - `:token_sig_transport` is either `:bearer` (default) or `:cookie`
    - `:upsert_session_opts` (default `[]`) as defined in `t:Charon.SessionPlugs.upsert_session_opts/0`
  """
  @spec create_session(any, Charon.Config.t(),
          token_sig_transport: :bearer | :cookie,
          upsert_session_opts: SessionPlugs.upsert_session_opts()
        ) ::
          test_session
  def create_session(user_id, config, opts \\ []) do
    Plug.Test.conn(:get, "/")
    |> Utils.set_user_id(user_id)
    |> Utils.set_token_transport(opts[:token_sig_transport] || :bearer)
    |> SessionPlugs.upsert_session(config, opts[:upsert_session_opts] || [])
    |> then(fn conn ->
      %{
        session: Utils.get_session(conn),
        tokens: Utils.get_tokens(conn),
        cookies: conn.resp_cookies
      }
    end)
  end

  @doc """
  Create a new test session and put a token (and its cookie when needed) on the conn.
  This is essentially `create_session/3` and `put_token_for/3` combined into one
  convenience function.

  ## Options

    - `:token_sig_transport` is either `:bearer` (default) or `:cookie`
    - `:token` is either `:access` (default) or `:refresh`
    - `:upsert_session_opts` (default `[]`) as defined in `t:Charon.SessionPlugs.upsert_session_opts/0`
  """
  @spec put_token(Conn.t(), any, Config.t(),
          token: :access | :refresh,
          token_sig_transport: :bearer | :cookie,
          upsert_session_opts: SessionPlugs.upsert_session_opts()
        ) :: Conn.t()
  def put_token(conn, user_id, config, opts \\ []) do
    create_session_opts = Keyword.take(opts, [:token_sig_transport, :upsert_session_opts])
    test_session = create_session(user_id, config, create_session_opts)
    put_token_for(conn, test_session, Keyword.take(opts, [:token]))
  end

  @doc """
  Put a token (and its cookie when needed) from the test session on the conn.
  Use `create_session/3` to create the test session.

  ## Options

    - `:token` is either `:access` (default) or `:refresh`
  """
  @spec put_token_for(Conn.t(), test_session(), token: :access | :refresh) :: Conn.t()
  def put_token_for(conn, test_session, opts \\ []) do
    token = resolve_token_type(opts)
    %{cookies: cookies, tokens: %{^token => token}} = test_session
    conn |> put_bearer_token(token) |> put_req_cookies(cookies)
  end

  ###########
  # Private #
  ###########

  defp put_bearer_token(conn, token) do
    Conn.put_req_header(conn, "authorization", "Bearer #{token}")
  end

  defp put_req_cookies(conn, cookies) do
    Enum.reduce(cookies, conn, fn {k, v}, c -> Plug.Test.put_req_cookie(c, k, v.value) end)
  end

  defp resolve_token_type(opts) do
    token = opts[:token] || :access
    Map.fetch!(%{access: :access_token, refresh: :refresh_token}, token)
  end
end
