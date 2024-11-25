defmodule Charon.Application do
  use Application

  # https://hexdocs.pm/elixir/main/design-anti-patterns.html#using-application-configuration-for-libraries

  def start(_type, _args) do
    Charon.Internal.Crypto.MachineId.init()

    children = [
      Charon.SessionSupervisor
    ]

    opts = [strategy: :one_for_one, name: Charon.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
