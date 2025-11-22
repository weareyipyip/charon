defmodule Charon.TokenPlugs.OrdsetClaimHasTest do
  use ExUnit.Case
  import Charon.TestUtils
  alias Charon.Utils
  alias Charon.TokenPlugs.OrdsetClaimHas

  describe "init/1" do
    test "normalizes keyword list with single claim and single value" do
      opts = OrdsetClaimHas.init(scope: "read")
      assert opts == [{"scope", {:all_of, ["read"]}}]
    end

    test "normalizes keyword list with single claim and list of values" do
      opts = OrdsetClaimHas.init(scope: ~w(read write))
      assert opts == [{"scope", {:all_of, ["read", "write"]}}]
    end

    test "normalizes keyword list with explicit :all_of operation" do
      opts = OrdsetClaimHas.init(scope: [all_of: ~w(read write)])
      assert opts == [{"scope", {:all_of, ["read", "write"]}}]
    end

    test "normalizes keyword list with explicit :any_of operation" do
      opts = OrdsetClaimHas.init(scope: [any_of: ~w(read write)])
      assert opts == [{"scope", {:any_of, ["read", "write"]}}]
    end

    test "normalizes map with string keys" do
      opts = OrdsetClaimHas.init(%{"scope" => "read"})
      assert opts == [{"scope", {:all_of, ["read"]}}]
    end

    test "normalizes map with atom keys" do
      opts = OrdsetClaimHas.init(%{scope: "read"})
      assert opts == [{"scope", {:all_of, ["read"]}}]
    end

    test "normalizes tuple format" do
      opts = OrdsetClaimHas.init({"scope", "read"})
      assert opts == [{"scope", {:all_of, ["read"]}}]
    end

    test "normalizes tuple format with list" do
      opts = OrdsetClaimHas.init({"scope", ~w(read write)})
      assert opts == [{"scope", {:all_of, ["read", "write"]}}]
    end

    test "handles multiple claims in keyword list" do
      opts = OrdsetClaimHas.init(scope: ~w(read write), role: ~w(admin user))
      assert opts == [{"role", {:all_of, ["admin", "user"]}}, {"scope", {:all_of, ["read", "write"]}}]
    end

    test "handles multiple claims with different operations" do
      opts =
        OrdsetClaimHas.init(scope: [all_of: ~w(read write)], role: [any_of: ~w(admin user)])

      assert opts == [{"role", {:any_of, ["admin", "user"]}}, {"scope", {:all_of, ["read", "write"]}}]
    end

    test "creates ordset from expected values" do
      opts = OrdsetClaimHas.init(scope: ~w(zebra apple banana banana))
      assert opts == [{"scope", {:all_of, ["apple", "banana", "zebra"]}}]
    end

    test "ignores empty list of values" do
      opts = OrdsetClaimHas.init(scope: [])
      assert opts == []
    end

    test "handles single value that is not a list" do
      opts = OrdsetClaimHas.init(scope: "read")
      assert opts == [{"scope", {:all_of, ["read"]}}]
    end

    test "raises on unsupported op" do
      assert_raise ArgumentError, fn ->
        OrdsetClaimHas.init(scope: [intersect: "read"])
      end
    end
  end

  defp init_and_call(conn \\ conn(), token_payload, init_opts) do
    opts = OrdsetClaimHas.init(init_opts)
    conn |> Utils.set_token_payload(token_payload) |> OrdsetClaimHas.call(opts)
  end

  describe "call/2 with :all_of operation" do
    test "passes when token claim contains all_of expected values" do
      conn = init_and_call(%{"scope" => ["read", "write"]}, scope: [all_of: ~w(read write)])
      refute Utils.get_auth_error(conn)
    end

    test "passes when token claim contains all_of expected values and more" do
      conn = init_and_call(%{"scope" => ["admin", "read", "write"]}, scope: [all_of: ~w(read write)])
      refute Utils.get_auth_error(conn)
    end

    test "fails when token claim is missing one expected value" do
      conn = init_and_call(%{"scope" => ["read"]}, scope: [all_of: ~w(read write)])
      assert Utils.get_auth_error(conn) == "bearer token claim scope invalid"
    end

    test "fails when token claim is empty" do
      conn = init_and_call(%{"scope" => []}, scope: [all_of: ~w(read write)])
      assert Utils.get_auth_error(conn) == "bearer token claim scope invalid"
    end

    test "passes with single expected value matching" do
      conn = init_and_call(%{"scope" => ["read", "write"]}, scope: "read")
      refute Utils.get_auth_error(conn)
    end
  end

  describe "call/2 with :any_of operation" do
    test "passes when token claim contains at least one expected value" do
      conn = init_and_call(%{"role" => ["admin", "user"]}, role: [any_of: ~w(admin superadmin)])
      refute Utils.get_auth_error(conn)
    end

    test "passes when token claim contains all_of expected values" do
      conn = init_and_call(%{"role" => ["admin", "moderator"]}, role: [any_of: ~w(admin moderator)])
      refute Utils.get_auth_error(conn)
    end

    test "fails when token claim contains none of the expected values" do
      conn = init_and_call(%{"role" => ["user", "guest"]}, role: [any_of: ~w(admin superadmin)])
      assert Utils.get_auth_error(conn) == "bearer token claim role invalid"
    end

    test "fails when token claim is empty" do
      conn = init_and_call(%{"role" => []}, role: [any_of: ~w(admin user)])
      assert Utils.get_auth_error(conn) == "bearer token claim role invalid"
    end

    test "passes with single matching value" do
      conn = init_and_call(%{"role" => ["user"]}, role: [any_of: ~w(admin user)])
      refute Utils.get_auth_error(conn)
    end
  end

  describe "call/2 with multiple claims" do
    test "passes when all_of claims are valid" do
      conn =
        init_and_call(
          %{"scope" => ["read", "write"], "role" => ["admin", "user"]},
          scope: [all_of: ~w(read write)],
          role: [any_of: ~w(admin moderator)]
        )

      refute Utils.get_auth_error(conn)
    end

    test "fails when first claim is invalid" do
      conn =
        init_and_call(
          %{"scope" => ["read"], "role" => ["admin"]},
          scope: [all_of: ~w(read write)],
          role: [any_of: ~w(admin moderator)]
        )

      assert Utils.get_auth_error(conn) == "bearer token claim scope invalid"
    end

    test "fails when second claim is invalid" do
      conn =
        init_and_call(
          %{"scope" => ["read", "write"], "role" => ["user"]},
          scope: [all_of: ~w(read write)],
          role: [any_of: ~w(admin moderator)]
        )

      assert Utils.get_auth_error(conn) == "bearer token claim role invalid"
    end

    test "stops at first error" do
      conn =
        init_and_call(
          %{"scope" => ["read"], "role" => ["user"]},
          scope: [all_of: ~w(read write)],
          role: [any_of: ~w(admin)]
        )

      # Should stop at first error (scope)
      assert Utils.get_auth_error(conn) == "bearer token claim scope invalid"
    end
  end

  describe "call/2 with missing claims" do
    test "fails when claim is not present in token" do
      conn = init_and_call(%{}, scope: "read")
      assert Utils.get_auth_error(conn) == "bearer token claim scope not found"
    end

    test "fails when one of multiple claims is missing" do
      conn =
        init_and_call(
          %{"scope" => ["read", "write"]},
          scope: [all_of: ~w(read write)],
          role: [any_of: ~w(admin)]
        )

      assert Utils.get_auth_error(conn) == "bearer token claim role not found"
    end
  end

  describe "call/2 early exit behavior" do
    test "passes through when auth error already present" do
      conn =
        conn()
        |> Charon.Utils.set_auth_error("previous error")
        |> init_and_call(%{"scope" => ["read"]}, scope: "write")

      assert Charon.Utils.get_auth_error(conn) == "previous error"
    end
  end

  describe "call/2 with empty config" do
    test "passes through when no claims to verify" do
      conn = init_and_call(%{"scope" => ["read"]}, scope: [])
      refute Utils.get_auth_error(conn)
    end
  end

  doctest OrdsetClaimHas
end
