defmodule Charon.Models.SessionTest do
  use ExUnit.Case, async: true
  alias Charon.Models.Session
  import Session

  @charon_config Charon.TestConfig.get()

  doctest Session
end
