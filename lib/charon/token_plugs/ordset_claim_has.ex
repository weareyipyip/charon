defmodule Charon.TokenPlugs.OrdsetClaimHas do
  @moduledoc """
  Verifies that bearer token payload claims contain expected values using `m::ordsets` (ordered set) operations.

  > #### Ordset requirement {: .warning}
  >
  > The verified token claims **must** be properly formatted `m::ordsets`.
  > The plug does not validate this - malformed values will produce incorrect results or errors.

  Like the other plugs in `Charon.TokenPlugs`, this plug short-circuits if errors have already been added to the connection, and it does not by itself halt the conn.

  Must be used after `Charon.TokenPlugs.verify_token_signature/2`.

  ## Comparison Operations

  Two comparison modes are supported:

  * `:all_of` (default) - The claim must contain **all** of the expected values
  * `:any_of` - The claim must contain **at least one** of the expected values

  ## Usage

  The plug accepts various initialization formats. All claims are converted to string keys,
  and expected values are normalized to ordered sets.

  Basic usage with keyword lists. This verifies two claims, both with the default `:all_of` operation.

      plug OrdsetClaimHas, scope: ~w(read write), role: "admin"

  Explicit operations can be passed along with the expected values.

      plug OrdsetClaimHas,
        scope: [all_of: ~w(read write)],
        role: [any_of: ~w(admin moderator)]

  You can also use maps or a tuple to initialize the plug.

      plug OrdsetClaimHas, %{scope: "read"}
      plug OrdsetClaimHas, %{"scope" => "read"}
      plug OrdsetClaimHas, {"scope", "read"}

  ## Examples

      # Verify token has both "read" and "write" scopes
      iex> opts = OrdsetClaimHas.init(scope: ~w(read write))
      iex> conn()
      ...> |> Charon.Utils.set_token_payload(%{"scope" => ["read", "write"]})
      ...> |> OrdsetClaimHas.call(opts)
      ...> |> Charon.Utils.get_auth_error()
      nil

      # Fails when required claim values are missing
      iex> opts = OrdsetClaimHas.init(scope: "write")
      iex> conn()
      ...> |> Charon.Utils.set_token_payload(%{"scope" => ["read"]})
      ...> |> OrdsetClaimHas.call(opts)
      ...> |> Charon.Utils.get_auth_error()
      "bearer token claim scope invalid"

      #  WARNING: if a token claim is not a proper ordset, this plug will NOT behave as expected!
      iex> opts = OrdsetClaimHas.init(scope: "write")
      iex> conn()
      ...> |> Charon.Utils.set_token_payload(%{"scope" => ["write", "read"]})
      ...> |> OrdsetClaimHas.call(opts)
      ...> |> Charon.Utils.get_auth_error()
      nil
  """
  @behaviour Plug
  use Charon.Internal.Constants
  import Charon.Utils

  @impl true
  def init(claims_and_expected) do
    # dedup, normalize claim name, make an :ordsets from expected
    # output: ["scope", {:all_of, ~w(read write)}]
    case claims_and_expected do
      {_claim, _expected} = tuple -> [tuple]
      coll when is_list(coll) or is_map(coll) -> coll
      _ -> raise ArgumentError, "must a tuple, map or keyword list"
    end
    |> Enum.map(fn {claim, expected} -> {to_string(claim), normalize_expected(expected)} end)
    |> Enum.reject(fn {_claim, {_op, expected}} -> expected == [] end)
    |> Map.new()
    |> Enum.to_list()
  end

  @ops [:any_of, :all_of]

  defp normalize_expected(expected) do
    case expected do
      [{op, vals}] when op in @ops -> {op, vals |> List.wrap() |> :ordsets.from_list()}
      [{op, _}] -> raise ArgumentError, "invalid operation #{op}, expected :any_of or :all_of"
      other -> normalize_expected(all_of: other)
    end
  end

  @impl true
  def call(conn, _) when is_map_key(conn.private, @auth_error), do: conn
  def call(conn = %{private: %{@bearer_token_payload => pl}}, init), do: verify(conn, init, pl)
  def call(_, _), do: raise("must be used after verify_token_signature/2")

  @compile {:inline, verify: 3}
  defp verify(conn, [], _), do: conn

  defp verify(conn, [{claim, {op, expected}} | tail], pl) do
    case pl do
      %{^claim => value} -> valid?(op, value, expected) |> maybe_put_err(conn, claim)
      _ -> set_auth_error(conn, "bearer token claim #{claim} not found")
    end
    |> verify(tail, pl)
  end

  @compile {:inline, [valid?: 3]}
  defp valid?(op, value, expected)
  defp valid?(:all_of, value, expected), do: :ordsets.is_subset(expected, value)
  defp valid?(:any_of, value, expected), do: not :ordsets.is_disjoint(value, expected)

  @compile {:inline, [maybe_put_err: 3]}
  defp maybe_put_err(result, conn, claim)
  defp maybe_put_err(true, conn, _), do: conn
  defp maybe_put_err(_, c, n), do: set_auth_error(c, "bearer token claim #{n} invalid")
end
