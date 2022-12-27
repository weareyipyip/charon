defmodule Charon.TokenPlugsTest do
  use ExUnit.Case
  use Charon.Internal.Constants
  alias Charon.{Utils, Internal}
  alias Charon.TestRedix
  alias Charon.TokenPlugs
  import Charon.TestUtils
  import Plug.Conn
  import Plug.Test
  import TestRedix, only: [command: 1]
  import TokenPlugs
  alias TokenPlugs.PutAssigns
  alias Charon.Models.Session

  @config Charon.TestConfig.get()

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
