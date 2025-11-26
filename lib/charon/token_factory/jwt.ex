defmodule Charon.TokenFactory.Jwt do
  @moduledoc """
  JWT's with either symmetric (HMAC) or asymmetric (EDDSA) signatures.
  The default, simplest and most performant option is symmetric signatures (MAC),
  with the key derived from the Charon base secret.

  Asymmetric tokens can be used when it is desirable for an external party
  to be able to verify a token's integrity,
  in which case distributing symmetric keys can be a hassle and a security risk.

  ## Keysets

  In order to sign and verify JWT's, a keyset is used.
  A keyset is a map of key ID's to keys.
  A key is a tuple of the signing algorithm and the actual secret(s).
  To simplify things and discourage key reuse,
  a key can only be used with a single signing algorithm.
  The default keyset looks like this, for example:

      %{"default" => {:hmac_sha256, <<0, ...>>}}

  Every token that is signed gets a `"kid"` claim in its header, allowing it to
  be verified with the specific key and algorithm that it was signed with.

  ### Key cycling

  It is possible to transition to a new signing key by adding a new key to the keyset
  and setting it as the new signing key using the `:signing_key` config option:

      %{
        "default" => {:hmac_sha256, <<0, ...>>},
        "new!" => {:hmac_sha512, <<1, ...>>}
      }

  Older tokens will be verified using the older key, based on their `"kid"` header claim.

  ### Tokens without a `"kid"` header claim

  Legacy or external tokens may not have a `"kid"` header claim.
  Such tokens can still be verified by adding
  a `"kid_not_set.<alg>"` (for example "kid_not_set.HS256")
  key to the keyset.

  ## Symmetric signatures

  Symmetric signatures are message authentication codes or MACs,
  either HMACs based on SHA256, 384 or 512,
  or a MAC generated using Poly1305,
  which can be used directly without using a HMAC wrapper.

  By default, a SHA256-based HMAC is used.

  ## Asymmetric signatures

  Asymmetric signatures are created using EDDSA (Edwards-curve Digital Signature Algorithm)
  based on Curve25519 or Curve448.
  Use in JWTs is standardized (pending) in [RFC 8073](https://datatracker.ietf.org/doc/rfc8037/).
  These algorithms were chosen for performance and implementation ease,
  since they offer built-in protection against many side-channel (timing) attacks and are
  not susceptible to nonce-reuse (technically, they are, but not on the part of the implementation,
  which means they are safe to use in your [PlayStation](https://en.wikipedia.org/wiki/EdDSA#Secure_coding)).
  Unless you are paranoid, use Curve25519, which offers about 128 bits of security.
  Curve448 offers about 224 bits, but is significantly slower.

  In order to use asymmetric signatures, generate a key using `gen_keypair/1`.
  Create a publishable JWK using `keypair_to_pub_jwk/1`.

  ## Config

  Additional config is required for this module:

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.TokenFactory.Jwt => %{
            get_keyset: fn -> %{"key1" => {:hmac_sha256, "my_key"}} end,
            signing_key: "key1"
          }
        }
      )

  The following options are supported:
    - `:get_keyset` (optional, default `default_keyset/1`). The keyset used to sign and verify JWTs. If not specified, a default keyset with a single key called "default" is used, which is derived from Charon's base secret.
    - `:signing_key` (optional, default "default"). The ID of the key in the keyset that is used to sign new tokens.
    - `:gen_poly1305_nonce` (optional, default `:random`). How to generate Poly1305-signed JWT nonces, can be overridden by a 0-arity function that must return a 96-bits binary. It is of critical importance that the nonce is unique for each invocation. The default random generation provides adequate security for most applications (collision risk becomes significant only after ~2^48 tokens). For extremely high-volume applications, consider using a counter-based approach via this option, for example using [NoNoncense](`e:no_noncense:NoNoncense.html`).

  ## Examples

  Generate and verify tokens with the default configuration:

      iex> {:ok, token} = sign(%{"user_id" => 123}, @charon_config)
      iex> {:ok, payload} = verify(token, @charon_config)
      iex> payload["user_id"]
      123

  Generate an asymmetric keypair and create a publishable JWK:

      iex> keypair = Jwt.gen_keypair(:eddsa_ed25519)
      iex> {:eddsa_ed25519, {_pubkey, _privkey}} = keypair
      iex> %{"crv" => "Ed25519", "kty" => "OKP", "x" => <<_::binary>>} = Jwt.keypair_to_pub_jwk(keypair)

  Use a custom keyset to rotate keys:

      iex> old_key = :crypto.strong_rand_bytes(32)
      iex> new_key = :crypto.strong_rand_bytes(32)
      iex> keyset = %{"old" => {:hmac_sha256, old_key}, "new" => {:hmac_sha512, new_key}}
      iex> old_config = Charon.TestHelpers.override_opt_mod_conf(@charon_config, Jwt, get_keyset: fn _ -> keyset end, signing_key: "old")
      iex> new_config = Charon.TestHelpers.override_opt_mod_conf(@charon_config, Jwt, get_keyset: fn _ -> keyset end, signing_key: "new")
      iex> {:ok, old_token} = sign(%{"uid" => 1}, old_config)
      iex> {:ok, new_token} = sign(%{"uid" => 2}, new_config)
      iex> {:ok, _} = verify(old_token, new_config)
      iex> {:ok, _} = verify(new_token, new_config)
  """
  alias Charon.Utils.{KeyGenerator, PersistentTermCache}
  import __MODULE__.Config, only: [get_mod_config: 1]
  import Charon.Internal
  import Charon.Internal.Crypto
  @behaviour Charon.TokenFactory.Behaviour

  @type hmac_alg :: :hmac_sha256 | :hmac_sha384 | :hmac_sha512
  @type eddsa_alg :: :eddsa_ed25519 | :eddsa_ed448
  @type mac_alg :: :poly1305
  @type eddsa_keypair :: {eddsa_alg(), {binary(), binary()}}
  @type symmetric_key :: {hmac_alg() | mac_alg(), binary()}
  @type key :: symmetric_key() | eddsa_keypair()
  @type keyset :: %{required(String.t()) => key()}

  @impl true
  def sign(payload, config) do
    jmod = config.json_module
    mod_conf = get_mod_config(config)
    %{get_keyset: get_keyset, signing_key: kid} = mod_conf

    with {:ok, _key = {alg, secret}} <- config |> get_keyset.() |> get_key(kid) do
      enc_payload = payload |> jmod.encode!() |> url_encode()
      nonce = new_poly1305_nonce(alg, mod_conf)
      key = {alg, gen_otk_for_nonce(secret, nonce)}
      header = create_header(alg, kid, nonce)
      data = [header, ?., enc_payload]
      signature = data |> do_sign(key) |> url_encode()
      token = [data, ?., signature] |> IO.iodata_to_binary()
      {:ok, token}
    else
      _ -> {:error, "could not create jwt"}
    end
  end

  @impl true
  def verify(token, config) do
    jmod = config.json_module
    %{get_keyset: get_keyset} = get_mod_config(config)

    with [header, payload, signature] <- dot_split(token, parts: 3),
         {:ok, kid, nonce} <- process_header(header, jmod),
         {:ok, signature} <- url_decode(signature),
         {:ok, {alg, secret}} <- config |> get_keyset.() |> get_key(kid),
         key = {alg, gen_otk_for_nonce(secret, nonce)},
         data = [header, ?., payload],
         {_, true} <- {:signature_valid, do_verify(data, key, signature)},
         {:ok, payload} <- url_json_decode(payload, jmod) do
      {:ok, payload}
    else
      {:signature_valid, _} -> {:error, "signature invalid"}
      error = {:error, _msg} -> error
      _ -> {:error, "malformed token"}
    end
  end

  @doc false
  def init_config(enum), do: __MODULE__.Config.from_enum(enum)

  @doc """
  Generate a new keypair for an asymmetrically signed JWT.
  """
  @spec gen_keypair(eddsa_alg) :: eddsa_keypair
  def gen_keypair(alg = :eddsa_ed25519), do: {alg, :crypto.generate_key(:eddsa, :ed25519)}
  def gen_keypair(alg = :eddsa_ed448), do: {alg, :crypto.generate_key(:eddsa, :ed448)}

  @doc """
  Convert a keypair generated by `gen_keypair/1` to a publishable JWK
  containing only the public key.
  """
  @spec keypair_to_pub_jwk(eddsa_keypair) :: map()
  def keypair_to_pub_jwk(_keypair = {eddsa_alg, {pubkey, _}}) do
    crv = Map.fetch!(%{eddsa_ed25519: "Ed25519", eddsa_ed448: "Ed448"}, eddsa_alg)
    %{"kty" => "OKP", "crv" => crv, "x" => url_encode(pubkey)}
  end

  @doc """
  Get the default keyset that is used if config option `:get_keyset` is not set explicitly.
  """
  @spec default_keyset(Charon.Config.t()) :: keyset()
  def default_keyset(config) do
    PersistentTermCache.get_or_create(__MODULE__, fn ->
      base_secret = config.get_base_secret.()
      default_key = KeyGenerator.derive_key(base_secret, "charon_jwt_default", log: false)
      %{"default" => {_default_alg = :hmac_sha256, default_key}}
    end)
  end

  ###########
  # Private #
  ###########

  @compile {:inline, get_key: 2}
  defp get_key(keyset, kid) do
    case keyset do
      %{^kid => key} -> {:ok, key}
      _ -> {:error, "key not found"}
    end
  end

  @compile {:inline, calc_hmac: 3}
  defp calc_hmac(data, key, alg), do: :crypto.mac(:hmac, alg, key, data)

  # Sign #
  defp do_sign(data, {:hmac_sha256, key}), do: calc_hmac(data, key, :sha256)
  defp do_sign(data, {:poly1305, otk}), do: :crypto.mac(:poly1305, otk, data)
  defp do_sign(data, {:hmac_sha384, key}), do: calc_hmac(data, key, :sha384)
  defp do_sign(data, {:hmac_sha512, key}), do: calc_hmac(data, key, :sha512)

  defp do_sign(data, {:eddsa_ed25519, {_, privkey}}),
    do: :crypto.sign(:eddsa, :none, data, [privkey, :ed25519])

  defp do_sign(data, {:eddsa_ed448, {_, privkey}}),
    do: :crypto.sign(:eddsa, :none, data, [privkey, :ed448])

  # Verify #
  defp do_verify(data, {:hmac_sha256, key}, signature),
    do: data |> calc_hmac(key, :sha256) |> constant_time_compare(signature)

  defp do_verify(data, {:poly1305, otk}, signature),
    do: :crypto.mac(:poly1305, otk, data) |> constant_time_compare(signature)

  defp do_verify(data, {:hmac_sha384, key}, signature),
    do: data |> calc_hmac(key, :sha384) |> constant_time_compare(signature)

  defp do_verify(data, {:hmac_sha512, key}, signature),
    do: data |> calc_hmac(key, :sha512) |> constant_time_compare(signature)

  defp do_verify(data, {:eddsa_ed25519, {pubkey, _privkey}}, signature),
    do: :crypto.verify(:eddsa, :none, data, signature, [pubkey, :ed25519])

  defp do_verify(data, {:eddsa_ed448, {pubkey, _privkey}}, signature),
    do: :crypto.verify(:eddsa, :none, data, signature, [pubkey, :ed448])

  @compile {:inline, new_poly1305_nonce: 2}
  defp new_poly1305_nonce(:poly1305, mod_conf) do
    case mod_conf.gen_poly1305_nonce do
      :random -> :crypto.strong_rand_bytes(12)
      function -> function.()
    end
  end

  defp new_poly1305_nonce(_, _), do: nil

  # strings whose lengths are multiples of 3 can be pre-encoded and concatenated
  @sha256_head ~s({"alg":"HS256","typ":"JWT","kid":) |> url_encode()
  @sha384_head ~s({"alg":"HS384","typ":"JWT","kid":) |> url_encode()
  @sha512_head ~s({"alg":"HS512","typ":"JWT","kid":) |> url_encode()
  @eddsa_head ~s({"alg":"EdDSA","typ":"JWT","kid":) |> url_encode()
  @poly1305_head ~s({"alg":"Poly1305","typ":"JWT","kid":) |> url_encode()

  @compile {:inline, create_header: 3}
  @doc false
  def create_header(:hmac_sha256, kid, _), do: [@sha256_head, url_encode(~s("#{kid}"}))]

  def create_header(:poly1305, kid, nonce) do
    [@poly1305_head, url_encode(~s("#{kid}","nonce":"#{url_encode(nonce)}"}))]
  end

  def create_header(:hmac_sha384, kid, _), do: [@sha384_head, url_encode(~s("#{kid}"}))]
  def create_header(:hmac_sha512, kid, _), do: [@sha512_head, url_encode(~s("#{kid}"}))]
  def create_header(:eddsa_ed25519, kid, _), do: [@eddsa_head, url_encode(~s("#{kid}"}))]
  def create_header(:eddsa_ed448, kid, _), do: [@eddsa_head, url_encode(~s("#{kid}"}))]

  defp url_json_decode(encoded, json_mod) do
    with {_, {:ok, json}} <- {:enc, url_decode(encoded)},
         {:ok, payload} <- json_mod.decode(json) do
      {:ok, payload}
    else
      {:enc, _} -> {:error, "encoding invalid"}
      _ -> {:error, "json invalid"}
    end
  end

  defp process_header(header, json_mod) do
    with {:ok, payload} <- url_json_decode(header, json_mod),
         {:ok, alg} <- get_header_alg(payload),
         kid = get_header_kid(payload, alg),
         {:ok, nonce} <- maybe_get_header_nonce(payload, alg) do
      {:ok, kid, nonce}
    else
      error -> error
    end
  end

  @compile {:inline, get_header_alg: 1}
  defp get_header_alg(_header_pl = %{"alg" => alg}), do: {:ok, alg}
  defp get_header_alg(_), do: {:error, "malformed header"}

  @compile {:inline, get_header_kid: 2}
  defp get_header_kid(%{"kid" => kid}, _), do: kid
  defp get_header_kid(_, alg), do: "kid_not_set.#{alg}"

  @compile {:inline, maybe_get_header_nonce: 2}
  defp maybe_get_header_nonce(header_pl, _alg = "Poly1305") do
    with %{"nonce" => nonce} <- header_pl,
         {:ok, nonce} <- url_decode(nonce) do
      {:ok, nonce}
    else
      _ -> {:error, "malformed header"}
    end
  end

  defp maybe_get_header_nonce(_, _), do: {:ok, nil}

  defp gen_otk_for_nonce(secret, nil), do: secret

  defp gen_otk_for_nonce(secret, nonce) do
    # after https://github.com/potatosalad/erlang-jose/blob/main/src/jwa/chacha20_poly1305/jose_chacha20_poly1305_crypto.erl#L58
    :crypto.crypto_one_time(:chacha20, secret, <<0::32, nonce::binary>>, <<0::256>>, true)
  end
end
