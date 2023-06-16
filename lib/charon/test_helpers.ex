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

    - `:upsert_session_opts` (default `[]`) as defined in `t:Charon.SessionPlugs.upsert_session_opts/0`
  """
  @spec create_session(Config.t(), SessionPlugs.upsert_session_opts()) :: test_session
  def create_session(config, upsert_session_opts \\ []) do
    Plug.Test.conn(:get, "/")
    |> SessionPlugs.upsert_session(
      config,
      Keyword.merge([token_transport: :bearer], upsert_session_opts)
    )
    |> then(fn conn ->
      %{
        session: Utils.get_session(conn),
        tokens: Utils.get_tokens(conn),
        cookies: conn.resp_cookies
      }
    end)
  end

  @type put_token_opts ::
          Keyword.merge(SessionPlugs.upsert_session_opts(), token: :access | :refresh)

  @doc """
  Create a new test session and put a token (and its cookie when needed) on the conn.
  This is essentially `create_session/3` and `put_token_for/3` combined into one
  convenience function.

  ## Options

    The upsert_session_opts defined in `t:Charon.SessionPlugs.upsert_session_opts/0` AND
    - `:token` is either `:access` (default) or `:refresh`
  """
  @spec put_token(Conn.t(), Config.t(), put_token_opts()) :: Conn.t()
  def put_token(conn, config, opts \\ []) do
    test_session = create_session(config, Keyword.drop(opts, [:token]))
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
