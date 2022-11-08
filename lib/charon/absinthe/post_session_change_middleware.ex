defmodule Charon.Absinthe.PostSessionChangeMiddleware do
  @moduledoc """
  Absinthe middleware to update the context after a session is created, refreshed or dropped.
  Transfers `resolution.value.resp_cookies` to context.
  """
  @behaviour Absinthe.Middleware

  @impl true
  def call(resolution = %{value: %{resp_cookies: resp_cookies}}, _config) do
    Charon.Internal.merge_context(resolution, %{resp_cookies: resp_cookies})
  end

  def call(resolution, _config), do: resolution
end
