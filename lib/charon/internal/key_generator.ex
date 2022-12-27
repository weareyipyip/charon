defmodule Charon.Internal.KeyGenerator do
  @moduledoc false
  @digest :sha512
  @iterations 200_000

  @doc """
  Get a derived secret for a given salt, derived from `config.get_base_secret` using PBKDF2.
  """
  @spec get_secret(binary, pos_integer, Charon.Config.t()) :: any
  def get_secret(salt, length, config) do
    cache = FastGlobal.get(__MODULE__) || %{}

    if cached = Map.get(cache, salt) do
      cached
    else
      :crypto.pbkdf2_hmac(@digest, config.get_base_secret.(), salt, @iterations, length)
      |> tap(&FastGlobal.put(__MODULE__, Map.put(cache, salt, &1)))
    end
  end
end
