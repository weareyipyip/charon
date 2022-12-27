defmodule Charon.Internal.ConfigTest do
  @moduledoc false
  import ExUnit.Assertions

  defp required_keys(config) do
    config |> Enum.filter(&match?({_k, :required}, &1)) |> Enum.map(fn {k, _} -> k end)
  end

  defp optional_keys(required_keys, config) do
    config |> Map.keys() |> Kernel.--(required_keys)
  end

  def test_optional(configurations) do
    for {mod, config} <- configurations do
      optional = config |> required_keys() |> optional_keys(config)

      for opt <- optional do
        val = config |> Map.delete(opt) |> mod.from_enum() |> Map.get(opt)

        default = config[opt]

        assert val == default,
               "expected #{inspect(default)} default value for :#{opt} of #{mod}"
      end
    end
  end

  def test_required(configurations) do
    for {mod, config} <- configurations do
      required = config |> required_keys()

      for req <- required do
        assert_raise ArgumentError, fn ->
          config |> Map.delete(req) |> mod.from_enum()
        end
      end
    end
  end
end
