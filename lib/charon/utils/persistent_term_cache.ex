defmodule Charon.Utils.PersistentTermCache do
  @moduledoc since: "4.0.0"
  @moduledoc """
  Cache things using `m::persistent_term`. Be careful when using this; `m::persistent_term` is only suitable for very read-heavy storage, to the point the cached item should probably be write-once-read-often.
  """

  @doc """
  Get the item stored under `key` from `m::persistent_term`. If it does not exist, create it using `create/0` and cache it under `key`.

  ## Doctests

      iex> create = fn -> "I'm cached" end
      iex> get_or_create(__MODULE__, create)
      "I'm cached"
      iex> create = fn -> "I'm never created" end
      iex> get_or_create(__MODULE__, create)
      "I'm cached"
  """
  @spec get_or_create(term(), (-> term())) :: term()
  def get_or_create(key, create) do
    if cached = :persistent_term.get(key, nil) do
      cached
    else
      create.() |> tap(&:persistent_term.put(key, &1))
    end
  end
end
