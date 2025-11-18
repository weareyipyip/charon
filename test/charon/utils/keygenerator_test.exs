defmodule Charon.Utils.KeygeneratorTest do
  use ExUnit.Case, async: false
  alias Charon.Utils.KeyGenerator
  import KeyGenerator
  import ExUnit.CaptureLog

  @moduletag :capture_log

  doctest KeyGenerator

  describe "derive_key/3" do
    test "logs function calls at specified level" do
      for lvl <- ~w(info warning error)a do
        log = capture_log(fn -> derive_key("secret", "test", iterations: 1, log: lvl) end)
        assert log =~ "deriving key (salt: test)"
      end
    end

    test "disables logs when log_level is false" do
      log = capture_log(fn -> derive_key("secret", "no_log_salt", iterations: 1, log: false) end)
      assert log == ""
    end
  end
end
