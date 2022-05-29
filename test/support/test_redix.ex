defmodule Charon.TestRedix do
  def init() do
    {Redix, name: :redix, host: System.get_env("REDIS_HOSTNAME", "localhost")}
    |> ExUnit.Callbacks.start_supervised!()
  end

  def before_each(), do: command(~w(FLUSHDB))
  def command(command), do: Redix.command(:redix, command)
  def pipeline(commands), do: Redix.pipeline(:redix, commands)
end
