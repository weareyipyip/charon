defmodule Charon.SessionPlugs.SessionUpdateConflictError do
  @moduledoc """
  Error raised on an optimistic locking error when updating an existing session.
  """
  defexception message: "A conflict occurred when updating a session. The update was cancelled.",
               plug_status: 409
end
