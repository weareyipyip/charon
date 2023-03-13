defmodule Charon.SessionStore.RedisStore.Config do
  @moduledoc """
  Config module for `Charon.SessionStore.RedisStore`.
  """
  alias Charon.SessionStore.RedisStore
  @enforce_keys []
  defstruct key_prefix: "charon_",
            get_signing_key: &RedisStore.default_signing_key/1,
            debug_log?: false

  @type t :: %__MODULE__{
          key_prefix: String.t(),
          get_signing_key: (Charon.Config.t() -> binary()),
          debug_log?: boolean
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum), do: struct!(__MODULE__, enum)

  @doc """
  Get the config for this module from the parent `Charon.Config` struct.
  """
  @spec get_mod_config(Charon.Config.t()) :: t()
  def get_mod_config(_charon_config = %{optional_modules: %{RedisStore => config}}), do: config
  def get_mod_config(_), do: from_enum([])
end
