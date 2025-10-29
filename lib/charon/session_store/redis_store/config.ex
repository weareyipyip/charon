defmodule Charon.SessionStore.RedisStore.Config do
  @moduledoc """
  Config module for `Charon.SessionStore.RedisStore`.
  """
  alias Charon.SessionStore.RedisStore
  @enforce_keys []
  defstruct [
    :redis_client_module,
    key_prefix: "charon_",
    get_signing_key: &RedisStore.default_signing_key/1
  ]

  @type t :: %__MODULE__{
          key_prefix: String.t(),
          get_signing_key: (Charon.Config.t() -> binary())
        }

  # def compile_init!(config) do
  #   mod_conf = RedisStore.get_mod_conf(config)
  #   mod_conf = struct!(__MODULE__, mod_conf) |> Map.from_struct()
  #   if(!mod_conf.redis_client_module, do: raise(":redis_client_module must be set"))
  #   Charon.OptMod.put_mod_conf(config, RedisStore, mod_conf)
  # end

  # def runtime_init!(config), do: compile_init!(config)
end
