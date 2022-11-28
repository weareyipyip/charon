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
            get_secret: fn -> :crypto.strong_rand_bytes(32) end,
            algorithm: :poly1305,
            json_module: Jason
          }
        }
      )

  The following options are supported:
    - `:get_secret` (required). A getter/0 for secret for the JWT's signature algorithm. Must be exactly 256 bits in case of Poly1305 alg.
    - `:algorithm` (optional). The token signature algorithm, may be `:sha256` (default), `:sha384`, `:sha512` or `:poly1305`.
    - `:json_module` (optional, default Jason). The JSON encoding lib.

  ## Deriving the secret from Phoenix's `:secret_key_base`

  It is possible to use Phoenix's `:secret_key_base` as the secret for the token factory.
  However, unlike `Phoenix.Token`, this module does not process the secret using PBKDF2 by default.
  This is not a problem when a dedicated secret is used, but in the case of `:secret_key_base`, the reuse of the secret will weaken security without such key derivation.
  It is very easy to add such preprocessing yourself, however, thanks to `Plug.Crypto.KeyGenerator`:

      defmodule MyApp.Charon do
        @token_salt "charon_token"

        def get_token_secret() do
          base_secret = Application.get_env(:my_app, MyAppWeb.Endpoint)[:secret_key_base]
          Plug.Crypto.KeyGenerator.generate(base_secret, @token_salt)
        end
      end

  And then pass `MyApp.Charon.get_token_secret/0` to this module's config, naturally.

  ## Examples / doctests

      @base_key :crypto.strong_rand_bytes(32)
      @payload %{"claim" => "value"}
      @mod_conf SymmetricJwt.Config.from_enum(get_secret: &__MODULE__.get_secret/0)
      @config %{optional_modules: %{SymmetricJwt => @mod_conf}}

      def get_secret(), do: @base_key

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

      # # poly1305 is experimentally supported, and requires a 256-bits key
      @poly1305_config %{optional_modules: %{SymmetricJwt => %{@mod_conf | algorithm: :poly1305}}}

      iex> {:ok, token} = sign(@payload, @poly1305_config)
      iex> verify(token, @poly1305_config)
      {:ok, @payload}
      iex> header = token |> String.split(".") |> List.first() |> Base.url_decode64!() |> Jason.decode!()
      iex> %{"alg" => "Poly1305", "nonce" => <<_::binary>>, "typ" => "JWT"} = header
      iex> wrong_secret_conf = %{optional_modules: %{SymmetricJwt => %{@mod_conf | get_secret: fn -> :crypto.strong_rand_bytes(32) end}}}
      iex> {:error, "signature invalid"} = verify(token, wrong_secret_conf)
  """
  @behaviour Charon.TokenFactory.Behaviour

  @encoding_opts padding: false
  @alg_to_header_map %{
    sha256: "HS256",
    sha384: "HS384",
    sha512: "HS512",
    poly1305: "Poly1305"
  }
  @header_to_alg_map Map.new(@alg_to_header_map, fn {k, v} -> {v, k} end)

  @impl true
  def sign(payload, config) do
    %{algorithm: alg, get_secret: get_secret, json_module: jmod} = get_module_config(config)
    secret = get_secret.()

    with {:ok, json_payload} <- jmod.encode(payload) do
      payload = url_encode(json_payload)
      {header_base_pl, secret} = gen_header_pl_and_secret(alg, secret)
      header = gen_header(header_base_pl, alg, jmod)
      token = generate_token(header, payload, alg, secret)
      {:ok, token}
    else
      _ -> {:error, "could not encode payload"}
    end
  end

  @impl true
  def verify(token, config) do
    %{get_secret: get_secret, json_module: jmod} = get_module_config(config)
    secret = get_secret.()

    with [header, payload, signature] <- String.split(token, ".", parts: 3),
         {:ok, alg, nonce} <- process_header(header, jmod),
         secret = generate_msg_secret(secret, nonce),
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

  defp get_module_config(%{optional_modules: %{__MODULE__ => config}}), do: config

  defp url_encode(bin), do: Base.url_encode64(bin, @encoding_opts)
  defp url_decode(bin), do: Base.url_decode64(bin, @encoding_opts)

  defp gen_header_pl_and_secret(:poly1305, secret) do
    nonce = :crypto.strong_rand_bytes(12)
    header = %{nonce: url_encode(nonce)}
    otk = gen_poly1305_key(secret, nonce)
    {header, otk}
  end

  defp gen_header_pl_and_secret(_alg, secret), do: {%{}, secret}

  defp generate_token(header, payload, alg, secret) do
    mac_base = [header, ?., payload]
    mac = calc_mac(mac_base, secret, alg) |> url_encode()
    [mac_base, ?., mac] |> IO.iodata_to_binary()
  end

  defp gen_header(base, alg, jmod) do
    base
    |> Map.merge(%{alg: Map.get(@alg_to_header_map, alg), typ: "JWT"})
    |> jmod.encode!()
    |> url_encode()
  end

  defp calc_mac(data, secret, :poly1305), do: :crypto.mac(:poly1305, secret, data)
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
      {:ok, alg, get_nonce_from_header_pl(payload)}
    else
      %{} -> {:error, "malformed header"}
      nil -> {:error, "unsupported signature algorithm"}
      error -> error
    end
  end

  defp get_nonce_from_header_pl(%{"nonce" => nonce}) when is_binary(nonce) do
    case url_decode(nonce) do
      {:ok, <<nonce::binary-size(12)>>} -> nonce
      _ -> nil
    end
  end

  defp get_nonce_from_header_pl(_), do: nil

  defp generate_msg_secret(secret, nil), do: secret
  defp generate_msg_secret(secret, nonce), do: gen_poly1305_key(secret, nonce)

  defp gen_poly1305_key(key, nonce) do
    :crypto.crypto_one_time(:chacha20, key, <<0::32, nonce::binary>>, <<0::256>>, true)
  end
end
