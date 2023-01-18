defmodule Charon.TestHelpers do
  @moduledoc """
  Utility functions for writing tests.
  """
  alias Charon.Config
  use Charon.Internal.Constants

  @doc """
  Override configuration for an optional module.
  """
  @spec override_opt_mod_conf(Config.t(), atom | binary(), map | keyword()) ::
          Config.t()
  def override_opt_mod_conf(config, module, overrides) do
    opt_mods = config.optional_modules
    mod_conf = opt_mods |> Map.get(module, %{}) |> Map.merge(Map.new(overrides))
    opt_mods = Map.merge(opt_mods, %{module => mod_conf})
    %{config | optional_modules: opt_mods}
  end
end
