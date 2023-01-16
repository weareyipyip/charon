defmodule Charon.Utils.KeygeneratorTest do
  use ExUnit.Case, async: false
  alias Charon.Utils.KeyGenerator
  import KeyGenerator

  setup do
    FastGlobal.delete(KeyGenerator)
    :ok
  end

  doctest KeyGenerator
end
