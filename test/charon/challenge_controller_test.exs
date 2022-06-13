defmodule Charon.ChallengeControllerTest do
  use ExUnit.Case
  use Charon.Constants
  use Plug.Test
  alias Charon.TestRedix
  alias Charon.UserContext
  alias Charon.ChallengeController
  alias Charon.AuthChallenge.RecoveryCodeChallenge

  @moduletag :capture_log
  @config Charon.AuthFlowController.get_config()

  setup_all do
    TestRedix.init()
    :ok
  end

  setup do
    TestRedix.before_each()
    :ok
  end

  defp init_setup(challenge, seeds) do
    conn(:post, "/init_setup/#{challenge}", %{})
    |> Plug.Conn.assign(:user_id, seeds.user.id)
    |> Plug.Conn.put_private(@token_signature_transport, :bearer)
    |> ChallengeController.call([])
  end

  defp complete_setup(challenge, seeds, params) do
    conn(:post, "/complete_setup/#{challenge}", params)
    |> Plug.Conn.assign(:user_id, seeds.user.id)
    |> ChallengeController.call([])
  end

  setup do
    {:ok, user} = UserContext.new(enabled_challenges: []) |> UserContext.insert()
    [user: user]
  end

  describe "password flow setup" do
    test "works", seeds do
      assert %{status: 204} = init_setup("password", seeds)

      assert %{status: 204} =
               complete_setup("password", seeds, %{
                 "password" => "boom",
                 "current_password" => seeds.user.password
               })

      assert %{password_hash: hash, enabled_challenges: ~w(password)} =
               UserContext.get_by_id(seeds.user.id)

      assert Bcrypt.verify_pass("boom", hash)
    end
  end

  describe "totp flow setup" do
    test "works", seeds do
      assert %{status: 200, resp_body: resp_body} = init_setup("totp", seeds)
      assert %{secret: secret, uri: _} = resp_body
      seed = secret |> Base.decode32!(padding: false)
      code = seed |> NimbleTOTP.verification_code()
      assert %{status: 204} = complete_setup("totp", seeds, %{"otp" => code})

      assert %{totp_seed: ^seed, enabled_challenges: ~w(totp)} =
               UserContext.get_by_id(seeds.user.id)

      assert seeds.user.totp_seed != seed
    end
  end

  describe "bypass_stage flow setup" do
    test "works", seeds do
      assert %{status: 200, resp_body: resp_body} = init_setup("bypass_stage", seeds)
      assert %{token: token} = resp_body
      user_id = seeds.user.id

      assert {:ok, %{"exp" => _, "sub" => ^user_id, "type" => "bypass_stage"}} =
               @config.token_factory_module.verify(token, @config)

      assert %{status: 204} = complete_setup("bypass_stage", seeds, %{})

      assert %{enabled_challenges: ~w(bypass_stage)} = UserContext.get_by_id(seeds.user.id)
    end
  end

  describe "recovery_code flow setup" do
    test "works", seeds do
      assert %{status: 200, resp_body: resp_body} = init_setup("recovery_code", seeds)
      assert %{recovery_codes: new_codes} = resp_body
      assert %{status: 204} = complete_setup("recovery_code", seeds, %{})

      assert user = UserContext.get_by_id(seeds.user.id)
      assert %{enabled_challenges: ~w(recovery_code)} = user
      assert user.recovery_code_hashes != seeds.user.recovery_code_hashes
      code = Enum.random(new_codes)

      assert :ok =
               RecoveryCodeChallenge.challenge_complete(user, %{"recovery_code" => code}, @config)

      assert user = UserContext.get_by_id(seeds.user.id)

      assert {:error, "recovery_code invalid"} =
               RecoveryCodeChallenge.challenge_complete(user, %{"recovery_code" => code}, @config)
    end
  end

  describe "pre_sent flow setup" do
    test "works", seeds do
      assert %{status: 204} = init_setup("pre_sent", seeds)
      assert %{status: 204} = complete_setup("pre_sent", seeds, %{})
      assert %{enabled_challenges: ~w(pre_sent)} = UserContext.get_by_id(seeds.user.id)
    end
  end
end
