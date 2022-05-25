defmodule Charon.Models.Tokens do
  @moduledoc """
  Tokens to be communicated to the client.
  """
  defstruct access_token: nil, refresh_token: nil, access_token_exp: nil, refresh_token_exp: nil

  @type t :: %__MODULE__{
          access_token: String.t(),
          refresh_token: String.t(),
          access_token_exp: integer,
          refresh_token_exp: integer
        }
end
