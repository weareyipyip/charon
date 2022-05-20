defmodule CharonTest do
  use ExUnit.Case
  doctest Charon

  test "greets the world" do
    assert Charon.hello() == :world
  end
end
