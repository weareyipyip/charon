defmodule Charon.Internal.Macros do
  @doc """
  Call a function statically by resolving a full capture to mod, name, and arity.
  """
  defmacro static_call(capture, arg) do
    # Expand the AST to resolve module attributes or aliases
    expanded_capture = Macro.expand(capture, __CALLER__)

    case expanded_capture do
      {:&, _, [{:/, _, [{{:., _, [mod, fun]}, _, []}, _arity]}]} ->
        quote do: unquote(mod).unquote(fun)(unquote(arg))

      {:{}, _, [mod, fun, arg]} ->
        quote do: unquote(mod).unquote(fun)(unquote(arg))

      _ ->
        raise ArgumentError, "You must pass #{inspect(capture)} as &Mod.fun/arity"
    end
  end
end
