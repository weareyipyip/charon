defmodule Charon.Models.SessionTest do
  use ExUnit.Case, async: true
  alias Charon.Models.Session
  import Session
  import Charon.TestUtils

  @charon_config Charon.Config.from_enum(token_issuer: "local")

  doctest Session
end
