defmodule Charon.Utils.PersistentTermCacheTest do
  use ExUnit.Case, async: false
  alias Charon.Utils.PersistentTermCache
  import PersistentTermCache

  setup do
    :persistent_term.erase(__MODULE__)
    :ok
  end

  doctest PersistentTermCache
end
