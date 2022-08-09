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

  defp init_setup(challenge, seeds, params) do
    conn(:post, "/init_setup/#{challenge}", params)
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
      assert %{status: 200, resp_body: %{"setup_challenge_token" => setup_token}} =
               init_setup("password", seeds, %{"password" => seeds.user.password})

      assert %{status: 204} =
               complete_setup("password", seeds, %{
                 "new_password" => "boomboom",
                 "setup_challenge_token" => setup_token
               })

      assert %{password_hash: hash, enabled_challenges: ~w(password)} =
               UserContext.get_by_id(seeds.user.id)

      assert Bcrypt.verify_pass("boomboom", hash)
    end
  end

  describe "totp flow setup" do
    test "works", seeds do
      assert %{
               status: 200,
               resp_body: %{"setup_challenge_token" => setup_token, secret: secret, uri: _}
             } = init_setup("totp", seeds, %{"password" => seeds.user.password})

      seed = secret |> Base.decode32!(padding: false)
      code = seed |> NimbleTOTP.verification_code()

      assert %{status: 204} =
               complete_setup("totp", seeds, %{
                 "setup_challenge_token" => setup_token,
                 "otp" => code
               })

      assert %{totp_seed: ^seed, enabled_challenges: ~w(totp)} =
               UserContext.get_by_id(seeds.user.id)

      assert seeds.user.totp_seed != seed
    end
  end

  describe "bypass_stage flow setup" do
    test "works", seeds do
      assert %{status: 200, resp_body: %{"setup_challenge_token" => setup_token}} =
               init_setup("bypass_stage", seeds, %{"password" => seeds.user.password})

      assert %{status: 200, resp_body: resp_body} =
               complete_setup("bypass_stage", seeds, %{"setup_challenge_token" => setup_token})

      assert %{token: token} = resp_body
      user_id = seeds.user.id

      assert {:ok, %{"exp" => _, "sub" => ^user_id, "type" => "charon_bypass_stage"}} =
               @config.token_factory_module.verify(token, @config)

      assert %{enabled_challenges: []} = UserContext.get_by_id(seeds.user.id)
    end
  end

  describe "recovery_code flow setup" do
    test "works", seeds do
      assert %{
               status: 200,
               resp_body: %{"setup_challenge_token" => setup_token, recovery_codes: new_codes}
             } = init_setup("recovery_code", seeds, %{"password" => seeds.user.password})

      assert %{status: 204} =
               complete_setup("recovery_code", seeds, %{"setup_challenge_token" => setup_token})

      assert user = UserContext.get_by_id(seeds.user.id)
      assert %{enabled_challenges: ~w(recovery_code)} = user
      assert user.recovery_code_hashes != seeds.user.recovery_code_hashes
      code = Enum.random(new_codes)

      assert {:ok, _, _} =
               RecoveryCodeChallenge.challenge_complete(
                 conn(:get, "/"),
                 %{"recovery_code" => code},
                 user,
                 @config
               )

      assert user = UserContext.get_by_id(seeds.user.id)

      assert {:error, "recovery_code invalid"} =
               RecoveryCodeChallenge.challenge_complete(
                 conn(:get, "/"),
                 %{"recovery_code" => code},
                 user,
                 @config
               )
    end
  end

  describe "pre_sent flow setup" do
    test "works", seeds do
      assert %{status: 200, resp_body: %{"setup_challenge_token" => setup_token}} =
               init_setup("pre_sent", seeds, %{"password" => seeds.user.password})

      assert %{status: 204} =
               complete_setup("pre_sent", seeds, %{"setup_challenge_token" => setup_token})

      assert %{enabled_challenges: ~w(pre_sent)} = UserContext.get_by_id(seeds.user.id)
    end
  end
end
