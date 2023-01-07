if Code.ensure_loaded?(Blake2.Blake2b) do
  defmodule Charon.TokenFactory.Jwt.Blake2b do
    def hash(data, key, digest_size),
      do: data |> IO.iodata_to_binary() |> Blake2.Blake2b.hash(key, digest_size)
  end
else
  defmodule Charon.TokenFactory.Jwt.Blake2b do
    def hash(_data, _key, _digest_size),
      do: raise("optional dependency :blake2_elixir not loaded")
  end
end
