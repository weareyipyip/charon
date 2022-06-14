defmodule Charon.AuthFlowControllerTest do
  use ExUnit.Case
  use Charon.Constants
  use Plug.Test
  alias Charon.TestRedix
  alias Charon.AuthChallenge
  alias Charon.UserContext
  alias Charon.AuthFlowController

  alias AuthChallenge.{
    TotpChallenge,
    BypassStageChallenge,
    PreSentChallenge
  }

  @moduletag :capture_log

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  defp init_challenge(challenge, params) do
    conn(:post, "/init_challenge/#{challenge}", params) |> AuthFlowController.call([])
  end

  defp complete_challenge(challenge, params) do
    conn(:post, "/complete_challenge/#{challenge}", params) |> AuthFlowController.call([])
  end

  describe "flow 'mfa' stage 0 challenge 'password'" do
    setup do
      {:ok, user} = UserContext.new() |> UserContext.insert()
      [user: user]
    end

    test "happy flow works", seeds do
      assert %{status: 201, resp_body: %{token: token}} =
               conn(:post, "/init_flow", %{
                 "flow" => "single",
                 "email" => seeds.user.email,
                 "token_sig_transport" => :cookie
               })
               |> AuthFlowController.call([])

      assert %{status: 204} = init_challenge("password", %{"token" => token})

      assert %{
               status: 201,
               resp_body: %{tokens: %{access_token: _}, session: _},
               resp_cookies: %{
                 "_access_token_signature" => %{
                   http_only: true,
                   max_age: 900,
                   same_site: "Strict",
                   secure: true,
                   value: <<_::binary>>
                 },
                 "_refresh_token_signature" => %{
                   http_only: true,
                   max_age: 5_184_000,
                   same_site: "Strict",
                   secure: true,
                   value: <<_::binary>>
                 }
               }
             } =
               complete_challenge("password", %{
                 "token" => token,
                 "challenge" => "password",
                 "password" => "supersecret"
               })
    end
  end

  def pass_stage_0(user) do
    assert %{status: 201, resp_body: %{token: token}} =
             conn(:post, "/init_flow", %{
               "flow" => "mfa",
               "email" => user.email,
               "token_sig_transport" => :bearer
             })
             |> AuthFlowController.call([])

    assert %{status: 204} = init_challenge("password", %{"token" => token})

    assert %{status: 200, resp_body: %{challenges: _}} =
             complete_challenge("password", %{
               "token" => token,
               "challenge" => "password",
               "password" => "supersecret"
             })

    %{token: token, user: user}
  end

  describe "flow 'mfa' stage 1 challenge 'totp'" do
    setup do
      {:ok, user} = UserContext.new() |> UserContext.insert()
      pass_stage_0(user)
    end

    test "happy flow works", seeds do
      assert %{status: 204} = init_challenge("totp", %{"token" => seeds.token})

      assert %{status: 201, resp_body: %{tokens: %{access_token: _}}} =
               complete_challenge("totp", %{
                 "token" => seeds.token,
                 "otp" => TotpChallenge.generate_code(seeds.user, AuthFlowController.get_config())
               })
    end
  end

  describe "flow 'mfa' stage 1 challenge 'pre_sent'" do
    setup do
      {:ok, user} = UserContext.new() |> UserContext.insert()
      pass_stage_0(user)
    end

    test "happy flow works", seeds do
      assert %{status: 204} = init_challenge("pre_sent", %{"token" => seeds.token})

      assert %{status: 201, resp_body: %{tokens: %{access_token: _}}} =
               complete_challenge("pre_sent", %{
                 "token" => seeds.token,
                 "otp" =>
                   PreSentChallenge.generate_code(seeds.user, AuthFlowController.get_config())
               })
    end
  end

  describe "flow 'mfa' stage 1 challenge 'bypass_stage'" do
    setup do
      {:ok, user} = UserContext.new() |> UserContext.insert()
      pass_stage_0(user)
    end

    test "happy flow works", seeds do
      assert %{status: 204} = init_challenge("bypass_stage", %{"token" => seeds.token})

      assert %{status: 201, resp_body: %{tokens: %{access_token: _}}} =
               complete_challenge("bypass_stage", %{
                 "token" => seeds.token,
                 "bypass_stage_token" =>
                   BypassStageChallenge.generate_token(
                     seeds.user,
                     AuthFlowController.get_config()
                   )
               })
    end
  end

  describe "flow 'mfa' stage 1 challenge 'recovery_code'" do
    setup do
      base = :crypto.strong_rand_bytes(16)
      code = base |> Base.encode32(padding: false, case: :lower)
      hash = :crypto.hash(:blake2b, base) |> Base.url_encode64(padding: false)
      {:ok, user} = UserContext.new(recovery_code_hashes: [hash]) |> UserContext.insert()
      pass_stage_0(user) |> Map.merge(%{code: code})
    end

    test "happy flow works", seeds do
      assert %{status: 204} = init_challenge("recovery_code", %{"token" => seeds.token})

      assert %{status: 201, resp_body: %{tokens: %{access_token: _}}} =
               complete_challenge("recovery_code", %{
                 "token" => seeds.token,
                 "recovery_code" => seeds.code
               })
    end
  end
end
