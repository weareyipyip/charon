defmodule Charon.Absinthe.IntegrationTest do
  use ExUnit.Case
  use Charon.Constants

  alias Absinthe.{Resolution, Blueprint}
  alias Blueprint.Execution
  alias Plug.Conn

  alias Charon.Absinthe.{
    HydrateContextPlug,
    ReqAuthMiddleware,
    ReqRefreshAuthMiddleware,
    PostSessionChangeMiddleware
  }

  def get_secret(), do: "supersecret"

  @absinthe_config %{
    access_token_pipeline: __MODULE__.Authorized,
    refresh_token_pipeline: __MODULE__.Authorized,
    auth_error_handler: &__MODULE__.handle_auth_error/2
  }

  defp config(absinthe_config) do
    Charon.Config.from_enum(
      token_issuer: "my_test_app",
      session_store_module: Charon.SessionStore.DummyStore,
      optional_modules: %{
        Charon.TokenFactory.SymmetricJwt => %{get_secret: &__MODULE__.get_secret/0},
        Charon.Absinthe => absinthe_config
      }
    )
  end

  defmodule Authorized do
    def call(conn, _), do: Conn.assign(conn, :user_id, 1)
  end

  defmodule Unauthorized do
    def call(conn, _), do: Charon.Internal.auth_error(conn, "boom!")
  end

  def handle_auth_error(resolution, reason) do
    Resolution.put_result(resolution, {:error, reason})
  end

  describe "access token auth check" do
    test "allows authorized requests" do
      config = @absinthe_config |> config()

      # hydrate context and create an absinthe resolution from it
      conn = HydrateContextPlug.call(%Conn{}, HydrateContextPlug.init(config))
      context = conn.private.absinthe.context
      resolution = %Resolution{context: context}

      # require auth
      result = ReqAuthMiddleware.call(resolution, config)
      assert ^resolution = result
    end

    test "rejects unauthorized requests" do
      config = %{@absinthe_config | access_token_pipeline: __MODULE__.Unauthorized} |> config()

      # hydrate context and create an absinthe resolution from it
      conn = HydrateContextPlug.call(%Conn{}, HydrateContextPlug.init(config))
      context = conn.private.absinthe.context
      resolution = %Resolution{context: context}

      # require auth
      result = ReqAuthMiddleware.call(resolution, config)
      assert %{resolution | state: :resolved, errors: ["boom!"]} == result
    end
  end

  describe "refresh token auth check" do
    test "allows authorized requests (even if invalid access token)" do
      config = %{@absinthe_config | access_token_pipeline: __MODULE__.Unauthorized} |> config()

      # hydrate context and create an absinthe resolution from it
      conn = HydrateContextPlug.call(%Conn{}, HydrateContextPlug.init(config))
      context = conn.private.absinthe.context
      resolution = %Resolution{context: context}

      # require refresh auth
      result = ReqRefreshAuthMiddleware.call(resolution, config)

      assert %Resolution{context: %{user_id: 1, charon_conn: %Conn{assigns: %{user_id: 1}}}} ==
               result
    end

    test "rejects unauthorized requests (even if valid access token)" do
      config = %{@absinthe_config | refresh_token_pipeline: __MODULE__.Unauthorized} |> config()

      # hydrate context and create an absinthe resolution from it
      conn = HydrateContextPlug.call(%Conn{}, HydrateContextPlug.init(config))
      context = conn.private.absinthe.context
      resolution = %Resolution{context: context}

      # require refresh auth
      result = ReqRefreshAuthMiddleware.call(resolution, config)

      assert %Resolution{
               state: :resolved,
               errors: ["boom!"],
               context: %{user_id: 1, charon_conn: %Conn{private: %{@auth_error => "boom!"}}}
             } == result
    end
  end

  describe "post-session change response cookie handling" do
    test "puts response cookies back into conn" do
      cookies = %{yum: "cookies!"}
      resolver_result = %Resolution{context: %{}, value: %{resp_cookies: cookies}}

      middleware_result = PostSessionChangeMiddleware.call(resolver_result, nil)
      assert %{resolver_result | context: %{@resp_cookies => cookies}} == middleware_result

      blueprint = %Blueprint{execution: %Execution{context: middleware_result.context}}

      conn = Charon.Absinthe.send_context_cookies(%Conn{}, blueprint)
      assert %Conn{resp_cookies: cookies} == conn
    end

    test "can handle a lack of cookies" do
      resolver_result = %Resolution{context: %{}, value: %{}}

      middleware_result = PostSessionChangeMiddleware.call(resolver_result, nil)
      assert %{resolver_result | context: %{}} == middleware_result

      blueprint = %Blueprint{execution: %Execution{context: middleware_result.context}}

      conn = Charon.Absinthe.send_context_cookies(%Conn{}, blueprint)
      assert %Conn{} == conn
    end
  end
end
