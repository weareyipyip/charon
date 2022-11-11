defmodule Charon.SessionStore.RedisStore.Config do
  @moduledoc """
  Config module for `Charon.SessionStore.RedisStore`.
  """
  @enforce_keys [:redix_module]
  defstruct [:redix_module, key_prefix: "charon_"]

  @type t :: %__MODULE__{redix_module: module(), key_prefix: String.t()}

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum), do: struct!(__MODULE__, enum)
end
