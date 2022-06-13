defmodule Charon.AuthChallenge.RecoveryCodeChallenge do
  @moduledoc """
  An auth challenge implementing MFA recovery codes.
  Setting up the challenge results in a list of codes for the user to store.
  """
  @challenge_name "recovery_code"
  use Charon.AuthChallenge
  alias Charon.Internal
  @custom_config_field :charon_recovery_code_challenge
  @defaults %{
    recovery_code_hashes_field: :recovery_code_hashes,
    new_recovery_code_hashes_field: :new_recovery_code_hashes,
    param: "recovery_code"
  }
  @required []

  @impl true
  def challenge_complete(user, params, config) do
    with :ok <- AuthChallenge.verify_enabled(user, @challenge_name, config) do
      %{recovery_code_hashes_field: field, param: param} = process_config(config)

      hashes = Map.fetch!(user, field)
      decoded_hashes = hashes |> Enum.map(&Base.url_decode64!(&1, padding: false))
      recovery_code = Map.fetch!(params, param)

      with {:ok, decoded} <- Base.decode32(recovery_code, padding: false, case: :lower),
           hash = :crypto.hash(:blake2b, decoded),
           hash_index when not is_nil(hash_index) <-
             Enum.find_index(decoded_hashes, &Plug.Crypto.secure_compare(&1, hash)) do
        {:ok, _} =
          AuthChallenge.update_user(user, %{field => List.delete_at(hashes, hash_index)}, config)

        :ok
      else
        _ -> {:error, "#{param} invalid"}
      end
    end
  end

  @impl true
  def setup_init(user, conn, config) do
    %{new_recovery_code_hashes_field: new_field} = process_config(config)

    1..8
    |> Enum.reduce({[], []}, fn _, {for_user, for_storage} ->
      code = :crypto.strong_rand_bytes(16)
      encoded_code = code |> Base.encode32(padding: false, case: :lower)
      # TODO: is this secure? I think it is, because the code entropy is high enough (128 bits)
      hash = :crypto.hash(:blake2b, code) |> Base.url_encode64(padding: false)
      {[encoded_code | for_user], [hash | for_storage]}
    end)
    |> then(fn {for_user, for_storage} ->
      {:ok, _user} = AuthChallenge.update_user(user, %{new_field => for_storage}, config)
      {:ok, %{recovery_codes: for_user}, conn}
    end)
  end

  @impl true
  def setup_complete(user, _params, config) do
    # user "ok" click is enough
    %{new_recovery_code_hashes_field: new_field, recovery_code_hashes_field: field} =
      process_config(config)

    hashes = Map.get(user, new_field)
    enabled = AuthChallenge.put_enabled(user, @challenge_name, config)
    params = %{field => hashes, config.enabled_auth_challenges_field => enabled}
    {:ok, _user} = AuthChallenge.update_user(user, params, config)
    :ok
  end

  ###########
  # Private #
  ###########

  defp process_config(config) do
    Internal.process_custom_config(config, @custom_config_field, @defaults, @required)
  end
end
