defmodule Charon.Models.SessionTest do
  use ExUnit.Case, async: true
  alias Charon.Models.Session
  import Session

  @charon_config TestApp.Charon.get()

  doctest Session

  describe "upgrade_version/2" do
    test "upgrades old version without :version and :refresh_expires_at fields" do
      session =
        %{
          __struct__: Session,
          created_at: 0,
          expires_at: 1,
          extra_payload: %{},
          id: "ab",
          refresh_token_id: "cd",
          refreshed_at: 15,
          type: :full,
          user_id: 9
        }
        |> upgrade_version(@charon_config)

      assert %Session{
               created_at: 0,
               expires_at: 1,
               extra_payload: %{},
               id: "ab",
               prev_tokens_fresh_from: 0,
               refresh_expires_at: 1,
               refresh_token_id: "cd",
               refreshed_at: 15,
               tokens_fresh_from: 15,
               type: :full,
               user_id: 9,
               version: 7
             } = session
    end

    test "upgrades old version with :expires_at = nil without error" do
      session =
        %{
          __struct__: Session,
          created_at: 0,
          expires_at: nil,
          extra_payload: %{},
          id: "ab",
          refresh_token_id: "cd",
          refreshed_at: 15,
          type: :full,
          user_id: 9
        }
        |> upgrade_version(@charon_config)

      assert %Session{
               created_at: 0,
               expires_at: :infinite,
               extra_payload: %{},
               id: "ab",
               prev_tokens_fresh_from: 0,
               refresh_expires_at: refresh_exp,
               refresh_token_id: "cd",
               refreshed_at: 15,
               tokens_fresh_from: 15,
               type: :full,
               user_id: 9,
               version: 7
             } = session

      assert is_integer(refresh_exp) and refresh_exp >= System.os_time(:second)
    end
  end
end
