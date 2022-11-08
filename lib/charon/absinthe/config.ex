defmodule Charon.Absinthe.Config do
  @moduledoc """
  Config module for `Charon.Absinthe`.

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.Absinthe => %{
            access_token_pipeline: MyApp.AccessTokenPipeline,
            refresh_token_pipeline: MyApp.RefreshTokenPipeline,
            auth_error_handler: &MyApp.Absinthe.auth_error_handler/2
          }
        }
      )

  The following options are supported:
    - `:access_token_pipeline` (required). A Plug that validates an access token (see readme).
    - `:refresh_token_pipeline` (required). A Plug that validates a refresh token (see readme).
    - `:auth_error_handler` (required). A function that takes an `%Absinthe.Resolution{}` struct and an error message, and returns the resolution struct.
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
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum), do: struct!(__MODULE__, enum)
end
