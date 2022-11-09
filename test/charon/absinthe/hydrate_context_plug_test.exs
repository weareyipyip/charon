defmodule Charon.Absinthe.HydrateContextPlugTest do
  use ExUnit.Case, async: true
  alias Plug.Conn
  alias Charon.Absinthe, as: CharonAbsinthe
  alias Charon.Absinthe.HydrateContextPlug

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
  def handle_auth_error(resolution, _reason), do: %{resolution | state: :resolved}

  describe "the thing" do
    test "puts processed conn, original conn and processed conn's assigns in absinthe context" do
      opts = HydrateContextPlug.init(@config)
      init_conn = %Conn{}
      conn = HydrateContextPlug.call(init_conn, opts)

      assert %{
               access_token_pipeline_conn: %Conn{assigns: %{user_id: 1}},
               preauth_conn: ^init_conn,
               user_id: 1
             } = conn.private.absinthe.context
    end
  end
end
