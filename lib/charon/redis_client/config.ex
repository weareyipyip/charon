defmodule Charon.RedisClient.Config do
  @moduledoc """
  Config module for `Charon.RedisClient`.
  """

  @enforce_keys []
  defstruct [:pool_name, pool_size: 5, pool_max_overflow: 3, redix_opts: []]

  @type t :: %__MODULE__{
          # with_connection: ((Redix.connection() -> any()) -> any())
        }

  # def compile_init!(config) do
  #   mod_conf = RedisClient.get_mod_conf(config)
  #   mod_conf = struct!(__MODULE__, mod_conf) |> Map.from_struct()
  #   if(!mod_conf.pool_name, do: raise(":pool_name must be set"))
  #   Charon.OptMod.put_mod_conf(config, RedisClient, mod_conf)
  # end

  # def runtime_init!(compile_conf, runtime_conf) do
  #   Charon.OptMod.def_runtime_init!(compile_conf, runtime_conf, RedisClient) |> compile_init!()
  # end
end
