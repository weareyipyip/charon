defmodule Charon.TokenPlugsTest do
  use ExUnit.Case
  use Charon.Constants
  alias Charon.{Utils, Internal}
  alias Charon.TestRedix
  alias Charon.TokenPlugs
  import Charon.TestUtils
  import Plug.Conn
  import Plug.Test
  import TestRedix, only: [command: 1]
  import TokenPlugs
  alias TokenPlugs.PutAssigns

  def update_user(user, _), do: {:ok, user}

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            update_user_callback: &__MODULE__.update_user/2,
            password_hashing_module: Bcrypt,
            custom: %{
              charon_symmetric_jwt: %{get_secret: &__MODULE__.get_secret/0},
              charon_redis_store: %{redix_module: TestRedix}
            }
          )
  @secret "supersecret"
  def get_secret(), do: @secret
  def sign(payload), do: Charon.TokenFactory.SymmetricJwt.sign(payload, @config) |> elem(1)

  def verify_read_scope(conn, value) do
    if "read" in String.split(value, ",") do
      conn
    else
      "no read scope"
    end
  end

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  doctest TokenPlugs
  doctest PutAssigns
end
