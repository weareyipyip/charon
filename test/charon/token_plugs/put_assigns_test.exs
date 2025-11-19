defmodule Charon.TokenPlugs.PutAssignsTest do
  use ExUnit.Case
  use Charon.Internal.Constants
  import Charon.TestUtils
  alias Charon.TokenPlugs.PutAssigns
  import Charon.Utils

  describe "PutAssigns" do
    test "assigns user_id, session_id, and token_payload from token claims" do
      opts = PutAssigns.init([])
      conn = conn() |> set_token_payload(%{"sub" => 1, "sid" => "a"})
      assigns = conn |> PutAssigns.call(opts) |> Map.get(:assigns)

      assert assigns == %{
               session_id: "a",
               token_payload: %{"sid" => "a", "sub" => 1},
               user_id: 1
             }
    end

    test "allows custom assign names for session" do
      opts = PutAssigns.init(session: :da_session_baby)
      conn = conn() |> set_token_payload(%{"sub" => 1, "sid" => "a"}) |> set_session("hii")
      assigns = conn |> PutAssigns.call(opts) |> Map.get(:assigns)

      assert assigns == %{
               session_id: "a",
               token_payload: %{"sid" => "a", "sub" => 1},
               user_id: 1,
               da_session_baby: "hii"
             }
    end

    test "skips assignment when auth error is present" do
      opts = PutAssigns.init([])

      conn =
        conn() |> set_token_payload(%{"sub" => 1, "sid" => "a"}) |> set_auth_error("boom")

      assigns = conn |> PutAssigns.call(opts) |> Map.get(:assigns)
      assert assigns == %{}
    end
  end

  doctest PutAssigns
end
