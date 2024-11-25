defmodule Charon.Internal.Crypto.MachineId do
  @moduledoc """
  Generate machine ids for safe generation of unique IDs / IVs.

  Based on https://github.com/blitzstudios/snowflake
  """

  @doc """
  Grabs hostname, fqdn, and ip addresses, then compares that list to the nodes
  config to find the intersection.
  """
  @spec machine_id() :: integer
  def machine_id(), do: Application.get_env(:ritsplit, :machine_id) |> machine_id()

  ###########
  # Private #
  ###########

  defp machine_id(nil) do
    node_list = Application.get_env(:ritsplit, :node_list) || []
    node_list = :ordsets.from_list(node_list)
    host_identifiers = [hostname(), fqdn(), Node.self()] ++ ip_addrs()
    host_identifiers = Enum.reject(host_identifiers, &is_nil/1) |> :ordsets.from_list()

    case :ordsets.intersection(host_identifiers, node_list) do
      [matching_node | _] ->
        Enum.find_index(node_list, &(&1 == matching_node))

      _ ->
        raise "machine ID could not be determined, possible identifiers: #{inspect(host_identifiers)}"
    end
  end

  defp machine_id(id) when id >= 0 and id < 1024, do: id

  defp ip_addrs() do
    {:ok, ifaddrs} = :inet.getifaddrs()

    ifaddrs
    |> Enum.map(fn {_name, props} -> props[:addr] end)
    |> Enum.reject(&is_nil/1)
    |> Enum.map(fn addr -> addr |> :inet.ntoa() |> to_string() end)
  end

  defp hostname() do
    {:ok, name} = :inet.gethostname()
    to_string(name)
  end

  defp fqdn() do
    case :inet.get_rc()[:domain] do
      nil -> nil
      domain -> hostname() <> "." <> to_string(domain)
    end
  end
end
