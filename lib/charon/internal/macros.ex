defmodule Charon.Internal.Macros do
  @doc """
  Call a function statically by resolving a full capture to mod, name, and arity.
  """
  defmacro static_call(capture, args \\ []) do
    # Expand the AST to resolve module attributes or aliases
    expanded_capture = Macro.expand(capture, __CALLER__)

    # Ensure args is a list
    args_list =
      case args do
        {:__block__, _, list} -> list
        list when is_list(list) -> list
        single -> [single]
      end

    case expanded_capture do
      {:&, _, [{:/, _, [{{:., _, [mod, fun]}, _, []}, _arity]}]} ->
        quote do: unquote(mod).unquote(fun)(unquote_splicing(args_list))

      {:{}, _, [mod, fun, _arity]} ->
        quote do: unquote(mod).unquote(fun)(unquote_splicing(args_list))

      _ ->
        raise ArgumentError, "You must pass #{inspect(capture)} as &Mod.fun/arity"
    end
  end
end
