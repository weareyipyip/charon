defmodule Charon.Utils.CryptoTest do
  use ExUnit.Case, async: true
  alias Charon.Utils.Crypto
  import Crypto

  @key <<43, 174, 120, 110, 62, 41, 62, 164, 202, 99, 83, 37, 249, 220, 141, 107, 100, 134, 117,
         106, 218, 69, 234, 61, 172, 57, 117, 185, 145, 40, 25, 255>>
  @wrong_key <<232, 111, 192, 185, 177, 205, 141, 32, 158, 126, 100, 146, 16, 49, 97, 144, 236,
               38, 216, 67, 37, 243, 34, 65, 76, 210, 90, 29, 95, 179, 169, 211>>

  describe "encryption" do
    test "works" do
      assert {:ok, "hello world"} = "hello world" |> encrypt(@key) |> decrypt(@key)
    end

    test "fails graciously" do
      assert {:error, :decryption_failed} =
               <<159, 70, 130, 39, 86, 28, 250, 2, 68, 155, 255, 136, 37, 108, 191, 229, 119, 115,
                 50, 159, 53, 42, 107, 147, 176, 82, 33, 38>>
               |> decrypt(@wrong_key)
    end
  end

  describe "constant_time_compare/2" do
    if function_exported?(:crypto, :hash_equals, 2) do
      test "raises ArgumentError on different size binaries" do
        assert_raise ArgumentError, fn ->
          constant_time_compare(<<0>>, <<1, 2>>)
        end
      end
    end
  end

  doctest Crypto
end
