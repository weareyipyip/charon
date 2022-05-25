defmodule Charon.Models.Session do
  @moduledoc """
  A session.
  """
  defstruct created_at: nil,
            expires_at: nil,
            extra_payload: %{},
            id: nil,
            refresh_token_id: nil,
            refreshed_at: nil,
            user_id: nil

  @type t :: %__MODULE__{
          created_at: integer,
          expires_at: integer | nil,
          extra_payload: map(),
          id: String.t(),
          refresh_token_id: String.t(),
          refreshed_at: integer,
          user_id: pos_integer | binary()
        }
end
