defmodule Charon.SessionPlugs.SessionStorageError do
  @moduledoc """
  Error raised when a new/updated session could not be stored.
  """
  defexception message:
                 "An error occurred when storing a new/updated session. The operation was cancelled.",
               plug_status: 500
end
