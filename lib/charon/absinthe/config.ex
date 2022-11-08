defmodule Charon.Absinthe.Config do
  @moduledoc """
  Config module for `Charon.Absinthe`.
  """
  @enforce_keys [:access_token_pipeline, :refresh_token_pipeline, :auth_error_handler]
  defstruct [:access_token_pipeline, :refresh_token_pipeline, :auth_error_handler]

  @type t :: %__MODULE__{
          access_token_pipeline: module(),
          refresh_token_pipeline: module(),
          auth_error_handler: (Absinthe.Resolution.t(), String.t() -> Absinthe.Resolution.t())
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  """
  @spec from_enum(Enum.t()) :: %__MODULE__{}
  def from_enum(enum), do: struct!(__MODULE__, enum)
end
