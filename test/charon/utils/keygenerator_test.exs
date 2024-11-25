defmodule Charon.Utils.KeygeneratorTest do
  use ExUnit.Case, async: false
  alias Charon.Utils.KeyGenerator
  import KeyGenerator

  setup do
    :persistent_term.erase(KeyGenerator)
    :ok
  end

  doctest KeyGenerator
end
