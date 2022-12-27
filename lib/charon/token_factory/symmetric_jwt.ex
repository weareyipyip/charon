defmodule Charon.TokenFactory.SymmetricJwt do
  @moduledoc """
  The default and most simple form of self-signed tokens,
  JWTs with symmetric-key signatures.
  These are suited for everything but OpenID Connect implementations,
  because these require third parties to verify the token signature,
  which requires asymetric keys.

  ## Config

  Additional config is required for this module (see `Charon.TokenFactory.SymmetricJwt.Config`):

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.TokenFactory.SymmetricJwt => %{
            secret_override: fn -> :crypto.strong_rand_bytes(32) end,
            algorithm: :sha256,
            json_module: Jason,
            gen_secret_salt: "salt"
          }
        }
      )

  The following options are supported:
    - `:secret_override` (optional). By default, the signing secret is derived from Charon's base secret. It is possible to override the signing secret for backwards compatibility.
    - `:algorithm` (optional). The token signature algorithm, may be `:sha256` (default), `:sha384`, or `:sha512`.
    - `:json_module` (optional, default Jason). The JSON encoding lib.
    - `:gen_secret_salt` (optional). The salt used to derive the token signing key.

  ## Examples / doctests

      @payload %{"claim" => "value"}
      @config Charon.TestConfig.get()
      @mod_conf @config.optional_modules |> Map.get(SymmetricJwt, SymmetricJwt.Config.default())
      @base_key Charon.Internal.KeyGenerator.get_secret(Map.get(@mod_conf, :gen_secret_salt), 32, @config)

      # verify ignores the config's algorithm, grabbing it from the JWT header instead
      # this allows changing algorithms without invalidating existing JWTs
      iex> {:ok, token} = sign(@payload, @config)
      iex> config = %{optional_modules: %{SymmetricJwt => %{@mod_conf | algorithm: :sha512}}}
      iex> verify(token, config)
      {:ok, @payload}

      # gracefully handles malformed tokens / unsupported algo's / invalid signature
      iex> verify("a", @config)
      {:error, "malformed token"}
      iex> verify("a.b.c", @config)
      {:error, "encoding invalid"}
      iex> header = %{"alg" => "boom"} |> Jason.encode!() |> Base.url_encode64(padding: false)
      iex> verify(header <> ".YQ.YQ", @config)
      {:error, "unsupported signature algorithm"}
      iex> header = %{"alg" => "HS256"} |> Jason.encode!() |> Base.url_encode64(padding: false)
      iex> verify(header <> ".YQ.YQ", @config)
      {:error, "signature invalid"}

      # supports overriding the signing key, for backwards compatibility
      iex> {:ok, token} = sign(@payload, @config)
      iex> config = %{optional_modules: %{SymmetricJwt => %{@mod_conf | secret_override: fn -> "supersecret but wrong" end}}}
      iex> verify(token, config)
      {:error, "signature invalid"}
  """
  alias Charon.Internal.KeyGenerator
  @behaviour Charon.TokenFactory.Behaviour

  @encoding_opts padding: false
  @alg_to_header_map %{
    sha256: "HS256",
    sha384: "HS384",
    sha512: "HS512"
  }
  @header_to_alg_map Map.new(@alg_to_header_map, fn {k, v} -> {v, k} end)

  @impl true
  def sign(payload, config) do
    %{algorithm: alg, secret_override: secret_override, json_module: jmod, gen_secret_salt: salt} =
      get_module_config(config)

    secret = get_secret(config, salt, secret_override)

    with {:ok, json_payload} <- jmod.encode(payload) do
      payload = url_encode(json_payload)
      header = gen_header(alg, jmod)
      token = generate_token(header, payload, alg, secret)
      {:ok, token}
    else
      _ -> {:error, "could not encode payload"}
    end
  end

  @impl true
  def verify(token, config) do
    %{secret_override: secret_override, json_module: jmod, gen_secret_salt: salt} =
      get_module_config(config)

    secret = get_secret(config, salt, secret_override)

    with [header, payload, signature] <- String.split(token, ".", parts: 3),
         {:ok, alg} <- process_header(header, jmod),
         mac_base = [header, ?., payload],
         mac = calc_mac(mac_base, secret, alg),
         {:ok, signature} <- url_decode(signature),
         true <- Plug.Crypto.secure_compare(mac, signature),
         {:ok, payload} <- to_map(payload, jmod) do
      {:ok, payload}
    else
      false -> {:error, "signature invalid"}
      error = {:error, <<_::binary>>} -> error
      _ -> {:error, "malformed token"}
    end
  end

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  ###########
  # Private #
  ###########

  defp get_secret(config, salt, override)
  defp get_secret(config, salt, nil), do: KeyGenerator.get_secret(salt, 32, config)
  defp get_secret(_, _, override), do: override.()

  defp get_module_config(%{optional_modules: %{__MODULE__ => config}}), do: config
  defp get_module_config(_), do: __MODULE__.Config.default()

  defp url_encode(bin), do: Base.url_encode64(bin, @encoding_opts)
  defp url_decode(bin), do: Base.url_decode64(bin, @encoding_opts)

  defp generate_token(header, payload, alg, secret) do
    mac_base = [header, ?., payload]
    mac = calc_mac(mac_base, secret, alg) |> url_encode()
    [mac_base, ?., mac] |> IO.iodata_to_binary()
  end

  defp gen_header(alg, jmod) do
    %{alg: Map.get(@alg_to_header_map, alg), typ: "JWT"} |> jmod.encode!() |> url_encode()
  end

  defp calc_mac(data, secret, alg), do: :crypto.mac(:hmac, alg, secret, data)

  defp to_map(encoded, json_mod) do
    with {:ok, json} <- url_decode(encoded),
         {:ok, payload} <- json_mod.decode(json) do
      {:ok, payload}
    else
      :error -> {:error, "encoding invalid"}
      error -> error
    end
  end

  defp process_header(header, json_mod) do
    with {:ok, payload} <- to_map(header, json_mod),
         %{"alg" => alg} <- payload,
         alg when not is_nil(alg) <- Map.get(@header_to_alg_map, alg) do
      {:ok, alg}
    else
      %{} -> {:error, "malformed header"}
      nil -> {:error, "unsupported signature algorithm"}
      error -> error
    end
  end
end
