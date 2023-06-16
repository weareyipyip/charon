defmodule Charon.SessionPlugs.InsecureTokenTransportError do
  @moduledoc """
  Error raised when token transport method "bearer" is requested by a browser client.
  """
  defexception message: "Token transport method bearer is not allowed for browser clients.",
               plug_status: 400
end
