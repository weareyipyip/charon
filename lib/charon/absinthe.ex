defmodule Charon.Absinthe do
  @moduledoc """
  Absinthe integration modules.

  ## How to use

  Follow the [readme](README.md#protecting-routes) until you've created token pipelines.

  ### Create an error handler

      defmodule MyAppWeb.Absinthe do
        def authentication_error(resolution, auth_error_msg) do
          message = "request could not be authenticated: \#{auth_error_msg}"
          extensions = %{error: "authentication_failure", reason: auth_error_msg}
          error = %{message: message, extensions: extensions}
          Absinthe.Resolution.put_result(resolution, {:error, error})
        end
      end

  ### Config

  Additional config is required for this module (see `Charon.Absinthe.Config`).
  Pass your access token pipeline, refresh token pipeline and error handler to the config module.

  ### Configure router

  Add a pipeline with the `Charon.Absinthe.HydrateContextPlug`, route the graphql endpoint through it,
  and register the `Charon.Absinthe.send_context_cookies/2` callback as an `Absinthe.Plug` `:before_send` hook.

      defmodule MyAppWeb.Router do
        use MyAppWeb, :router

        @config Application.compile_env(:my_app, :charon) |> Charon.Config.from_enum()

        pipeline :api do
          plug :accepts, ["json"]
        end

        pipeline :charon_auth do
          plug Charon.Absinthe.HydrateContextPlug, @config
        end

        scope "/api" do
          pipe_through :charon_auth

          forward "/graphql", Absinthe.Plug,
            schema: MyAppWeb.Absinthe.Schema,
            before_send: {Charon.Absinthe, :send_context_cookies}
        end
      end

  ### Protect your schema

  Normal "auth-required" fields must be protected with `Charon.Absinthe.ReqAuthMiddleware`.
  The refresh mutation must be protected with `Charon.Absinthe.ReqRefreshAuthMiddleware`.
  Mutations that alter the session (login, logout, refresh, logout-all, logout-other...) must be followed by `Charon.Absinthe.PostSessionChangeMiddleware`.

      defmodule MyAppWeb.Absinthe.SessionTypes do
        use Absinthe.Schema.Notation
        alias MyAppWeb.Absinthe.SessionResolver
        alias Charon.Absinthe.{ReqAuthMiddleware, ReqRefreshAuthMiddleware, PostSessionChangeMiddleware}

        @config Application.compile_env(:my_app, :charon) |> Charon.Config.from_enum()

        object :session_mutations do
          field :login, type: :login_payload do
            arg :email, non_null(:string)
            arg :password, non_null(:string)
            arg :token_signature_transport, non_null(:string)
            resolve &SessionResolver.login/3
            middleware PostSessionChangeMiddleware
          end

          field :logout, type: :logout_payload do
            middleware ReqAuthMiddleware, @config
            resolve &SessionResolver.logout/3
            middleware PostSessionChangeMiddleware
          end

          field :refresh, type: :refresh_payload do
            middleware ReqRefreshAuthMiddleware, @config
            resolve &SessionResolver.refresh/3
            middleware PostSessionChangeMiddleware
          end
        end
      end

  ### Create a session resolver

  Error handling is omitted.

      defmodule MyAppWeb.Absinthe.SessionResolver do
        alias Charon.{Utils, SessionPlugs}
        alias MyApp.{User, Users}

        @config Application.compile_env(:my_app, :charon) |> Charon.Config.from_enum()

        def login(
              _parent,
              _args = %{token_signature_transport: transport, email: email, password: password},
              _resolution = %{context: %{charon_conn: conn}}
            ) do
          with {:ok, user} <- Users.get_by(email: email) |> Users.verify_password(password) do
            conn
            |> Utils.set_token_signature_transport(transport)
            |> Utils.set_user_id(user.id)
            |> SessionPlugs.upsert_session(@config)
            |> token_response()
          end
        end

        def logout(_parent, _args, _resolution = %{context: %{charon_conn: conn}}) do
          conn
          |> SessionPlugs.delete_session(@config)
          |> then(fn conn -> {:ok, %{resp_cookies: conn.resp_cookies}} end)
        end

        def refresh(
              _parent,
              _args,
              _resolution = %{context: %{charon_conn: conn, user_id: user_id}}
            ) do
          with %User{status: "active"} <- Users.get_by(id: user_id) do
            conn |> SessionPlugs.upsert_session(@config) |> token_response()
          end
        end

        ###########
        # Private #
        ###########

        defp token_response(conn) do
          tokens = conn |> Utils.get_tokens() |> Map.from_struct()
          session = conn |> Utils.get_session() |> Map.from_struct()
          {:ok, %{resp_cookies: conn.resp_cookies, tokens: tokens, session: session}}
        end
      end
  """
  use Charon.Constants

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  @doc false
  def get_module_config(%{optional_modules: %{Charon.Absinthe => config}}), do: config

  @doc """
  Absinthe helper to send any response cookies present in the context.
  To be used as a `before_send` hook for `Absinthe.Plug`.
  Response cookies will be set by `Charon.Absinthe.PostSessionChangeMiddleware`.
  """
  @spec send_context_cookies(Plug.Conn.t(), Absinthe.Blueprint.t()) :: Plug.Conn.t()
  def send_context_cookies(
        conn,
        _blueprint = %{execution: %{context: %{@resp_cookies => resp_cookies}}}
      ) do
    %{conn | resp_cookies: Map.merge(conn.resp_cookies, resp_cookies)}
  end

  def send_context_cookies(conn, _), do: conn
end
