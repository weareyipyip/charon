defmodule Charon.TokenPlugsTest do
  use ExUnit.Case
  use Charon.Internal.Constants
  alias Charon.{Utils, Internal, TokenPlugs, SessionStore}
  import Charon.TestUtils
  import Utils
  import Plug.Conn
  import Plug.Test
  import TokenPlugs
  alias TokenPlugs.PutAssigns
  alias Charon.Models.Session

  @config Charon.TestConfig.get()

  def sign(payload), do: Charon.TokenFactory.Jwt.sign(payload, @config) |> elem(1)

  def verify_read_scope(conn, value) do
    if "read" in String.split(value, ",") do
      conn
    else
      "no read scope"
    end
  end

  setup do
    start_supervised!(Charon.SessionStore.LocalStore)
    :ok
  end

  doctest TokenPlugs
  doctest PutAssigns
end
