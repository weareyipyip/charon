defmodule Charon.Absinthe do
  @moduledoc """
  Abisnthe integration modules.
  """

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  @doc false
  def get_module_config(%{optional_modules: %{Charon.Absinthe => config}}), do: config

  @doc """
  Absinthe helper to send any `resp_cookies` present in the context.
  To be used as a `before_send` handler for `Absinthe.Plug`.
  Response cookies will be set by `Charon.Absinthe.PostSessionChangeMiddleware`.
  """
  @spec send_context_cookies(Plug.Conn.t(), map) :: Plug.Conn.t()
  def send_context_cookies(conn, %{execution: %{context: %{resp_cookies: resp_cookies}}}) do
    %{conn | resp_cookies: Map.merge(conn.resp_cookies, resp_cookies)}
  end

  def send_context_cookies(conn, _), do: conn
end
