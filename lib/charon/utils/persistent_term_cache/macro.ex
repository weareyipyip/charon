defmodule Charon.Utils.PersistentTermCache.Macro do
  @moduledoc false

  defmacro get_or_create(key, do: create_block) do
    quote do
      key = unquote(key)

      case :persistent_term.get(key, nil) do
        nil -> unquote(create_block) |> tap(&:persistent_term.put(key, &1))
        cached -> cached
      end
    end
  end
end
