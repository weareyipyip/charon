defmodule Charon.TokenFactory.SymmetricJwt.Poly1305NonceFactoryTest do
  use ExUnit.Case, async: true
  alias Charon.TokenFactory.SymmetricJwt.Poly1305NonceFactory, as: Factory

  # 16 bits
  @nonce_size 2
  @random_size 1

  setup do
    {:ok, _} =
      Factory.start_link(name: __MODULE__, nonce_size: @nonce_size, random_size: @random_size)

    :ok
  end

  describe "get_nonce/1" do
    test "returns different nonce of correct size" do
      assert <<nonce1::binary-size(@nonce_size)>> = Factory.get_nonce(__MODULE__)
      assert <<nonce2::binary-size(@nonce_size)>> = Factory.get_nonce(__MODULE__)
      assert nonce1 != nonce2
      assert :binary.decode_unsigned(nonce1) + 1 == :binary.decode_unsigned(nonce2)
    end

    test "handles multiple simultaneous nonce requests well" do
      task = fn -> Factory.get_nonce(__MODULE__) end
      count = 1000

      assert ^count =
               1..count
               |> Enum.map(fn _ -> Task.async(task) end)
               |> Task.yield_many(5000)
               |> Enum.map(fn {_task, {:ok, result}} -> result end)
               |> MapSet.new()
               |> MapSet.size()
    end
  end
end
