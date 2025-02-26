if Code.ensure_loaded?(Blake3) do
  defmodule Charon.TokenFactory.Jwt.Blake3 do
    @moduledoc false
    def keyed_hash(key, data), do: Blake3.keyed_hash(key, IO.iodata_to_binary(data))
  end
end
