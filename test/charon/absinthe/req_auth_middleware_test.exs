defmodule Charon.Absinthe.ReqAuthMiddlewareTest do
  use ExUnit.Case, async: true
  use Charon.Constants
  alias Plug.Conn
  alias Charon.Absinthe, as: CharonAbsinthe
  alias Charon.Absinthe.{ReqAuthMiddleware}
  alias Absinthe.Resolution

  @config %{
    optional_modules: %{
      CharonAbsinthe =>
        CharonAbsinthe.Config.from_enum(
          access_token_pipeline: __MODULE__,
          refresh_token_pipeline: __MODULE__,
          auth_error_handler: &__MODULE__.handle_auth_error/2
        )
    }
  }

  def call(conn, _), do: Conn.assign(conn, :user_id, 1)

  def handle_auth_error(resolution, reason) do
    Resolution.put_result(resolution, {:error, reason})
  end

  describe "call/2" do
    test "rejects unauthorized requests" do
      resolution = %Resolution{state: :unresolved, context: %{@auth_error => "boom"}}
      result = resolution |> ReqAuthMiddleware.call(@config)
      assert %{state: :resolved, errors: ["boom"]} = result
    end

    test "passes through authorized requests" do
      resolution = %Resolution{state: :unresolved}
      assert ^resolution = resolution |> ReqAuthMiddleware.call(@config)
    end
  end
end
