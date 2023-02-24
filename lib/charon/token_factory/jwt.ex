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
  or a MAC generated using Blake3's [keyed-hashing mode](https://docs.rs/blake3/latest/blake3/fn.keyed_hash.html),
  which can be used directly without using a HMAC wrapper.
  Using Blake3 requires the optional dependency [Blake3](https://hex.pm/packages/blake3)
  and a key of exactly 256 bits.

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

      iex> keypair = Jwt.gen_keypair(:eddsa_ed25519)
      iex> {:eddsa_ed25519, {_pubkey, _privkey}} = keypair
      iex> %{"crv" => "Ed25519", "kty" => "OKP", "x" => <<_::binary>>} = Jwt.keypair_to_pub_jwk(keypair)

  ## Config

  Additional config is required for this module (see `Charon.TokenFactory.Jwt.Config`):

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
    - `:get_keyset` (optional, default `default_keyset/0`). The keyset used to sign and verify JWTs. If not specified, a default keyset with a single key called "default" is used, which is derived from Charon's base secret.
    - `:signing_key` (optional, default "default"). The ID of the key in the keyset that is used to sign new tokens.

  ## Examples / doctests

      # gracefully handles malformed tokens / unsupported algo's / invalid signature
      iex> verify("a", @charon_config)
      {:error, "malformed token"}
      iex> verify("a.b.c", @charon_config)
      {:error, "encoding invalid"}
      iex> header = "notjson" |> url_encode()
      iex> verify(header <> ".YQ.YQ", @charon_config)
      {:error, "json invalid"}
      iex> header = %{"missing" => "alg"} |> Jason.encode!() |> url_encode()
      iex> verify(header <> ".YQ.YQ", @charon_config)
      {:error, "malformed header"}
      iex> header = %{"alg" => "boom"} |> Jason.encode!() |> url_encode()
      iex> verify(header <> ".YQ.YQ", @charon_config)
      {:error, "key not found"}
      iex> header = %{"alg" => "HS256", "kid" => "default"} |> Jason.encode!() |> url_encode()
      iex> verify(header <> ".YQ.YQ", @charon_config)
      {:error, "signature invalid"}

      # supports cycling to a new signing key, while still verifying old tokens
      iex> {:ok, token} = sign(%{}, @charon_config)
      iex> keyset = Jwt.default_keyset(@charon_config)
      iex> keyset = Map.put(keyset, "ed25519_1", Jwt.gen_keypair(:eddsa_ed25519))
      iex> config = override_opt_mod_conf(@charon_config, Jwt, get_keyset: fn _ -> keyset end, signing_key: "ed25519_1")
      iex> {:ok, _} = verify(token, config)
      iex> {:ok, new_token} = sign(%{}, config)
      iex> new_token == token
      false

      # an old / external / legacy token without a "kid" claim can still be verified
      # by adding a "kid_not_set.<alg>" key to the keyset
      # a token MUST have an alg claim, which is mandatory according to the JWT spec
      iex> [header, pl] = [%{"alg" => "HS256"}, %{}] |> Enum.map(&Jason.encode!/1) |> Enum.map(&url_encode/1)
      iex> base = "\#{header}.\#{pl}"
      iex> key = :crypto.strong_rand_bytes(32)
      iex> signature = :crypto.mac(:hmac, :sha256, key, base) |> url_encode()
      iex> token = "\#{base}.\#{signature}"
      iex> {:error, "key not found"} = verify(token, @charon_config)
      iex> keyset = %{"kid_not_set.HS256" => {:hmac_sha256, key}}
      iex> config = override_opt_mod_conf(@charon_config, Jwt, get_keyset: fn _ -> keyset end)
      iex> {:ok, _} = verify(token, config)
  """
  import Charon.Utils.KeyGenerator
  import __MODULE__.Config, only: [get_mod_config: 1]
  import Plug.Crypto, only: [secure_compare: 2]
  import Charon.Internal
  @behaviour Charon.TokenFactory.Behaviour

  @sign_alg_to_header_alg %{
    hmac_sha256: "HS256",
    hmac_sha384: "HS384",
    hmac_sha512: "HS512",
    eddsa_ed25519: "EdDSA",
    eddsa_ed448: "EdDSA",
    blake3_256: "Bl3_256"
  }

  @type hmac_alg :: :hmac_sha256 | :hmac_sha384 | :hmac_sha512
  @type eddsa_alg :: :eddsa_ed25519 | :eddsa_ed448
  @type mac_alg :: :blake3_256
  @type eddsa_keypair :: {eddsa_alg(), {binary(), binary()}}
  @type symmetric_key :: {hmac_alg() | mac_alg(), binary()}
  @type key :: symmetric_key() | eddsa_keypair()
  @type keyset :: %{required(String.t()) => key()}

  @impl true
  def sign(payload, config) do
    jmod = config.json_module
    %{get_keyset: get_keyset, signing_key: kid} = get_mod_config(config)

    with {:ok, key = {alg, _secret}} <- config |> get_keyset.() |> get_key(kid),
         {:ok, json_payload} <- jmod.encode(payload) do
      payload = url_encode(json_payload)
      header = gen_header(alg, kid, jmod)
      data = [header, ?., payload]
      signature = data |> do_sign(key) |> url_encode()
      token = [data | [?., signature]] |> IO.iodata_to_binary()
      {:ok, token}
    else
      _ -> {:error, "could not create jwt"}
    end
  end

  @impl true
  def verify(token, config) do
    jmod = config.json_module
    %{get_keyset: get_keyset} = get_mod_config(config)

    with [header, payload, signature] <- String.split(token, ".", parts: 3),
         {:ok, kid} <- process_header(header, jmod),
         data = [header, ?., payload],
         {:ok, key} <- config |> get_keyset.() |> get_key(kid),
         {:ok, signature} <- url_decode(signature),
         {_, true} <- {:signature_valid, do_verify(data, key, signature)},
         {:ok, payload} <- to_map(payload, jmod) do
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
    %{"default" => {:hmac_sha256, derive_key(config.get_base_secret.(), "charon_jwt_default")}}
  end

  ###########
  # Private #
  ###########

  defp get_key(keyset, kid) do
    if key = Map.get(keyset, kid) do
      {:ok, key}
    else
      {:error, "key not found"}
    end
  end

  defp calc_hmac(data, key, alg), do: :crypto.mac(:hmac, alg, key, data)

  # Sign #
  defp do_sign(data, {:hmac_sha256, key}), do: calc_hmac(data, key, :sha256)
  defp do_sign(data, {:hmac_sha384, key}), do: calc_hmac(data, key, :sha384)
  defp do_sign(data, {:hmac_sha512, key}), do: calc_hmac(data, key, :sha512)
  defp do_sign(data, {:blake3_256, key}), do: __MODULE__.Blake3.keyed_hash(key, data)

  defp do_sign(data, {:eddsa_ed25519, {_, privkey}}),
    do: :crypto.sign(:eddsa, nil, data, [privkey, :ed25519])

  defp do_sign(data, {:eddsa_ed448, {_, privkey}}),
    do: :crypto.sign(:eddsa, nil, data, [privkey, :ed448])

  # Verify #
  defp do_verify(data, {:hmac_sha256, key}, signature),
    do: data |> calc_hmac(key, :sha256) |> secure_compare(signature)

  defp do_verify(data, {:hmac_sha384, key}, signature),
    do: data |> calc_hmac(key, :sha384) |> secure_compare(signature)

  defp do_verify(data, {:hmac_sha512, key}, signature),
    do: data |> calc_hmac(key, :sha512) |> secure_compare(signature)

  defp do_verify(data, {:blake3_256, key}, sig),
    do: __MODULE__.Blake3.keyed_hash(key, data) |> secure_compare(sig)

  defp do_verify(data, {:eddsa_ed25519, {pubkey, _privkey}}, signature),
    do: :crypto.verify(:eddsa, nil, data, signature, [pubkey, :ed25519])

  defp do_verify(data, {:eddsa_ed448, {pubkey, _privkey}}, signature),
    do: :crypto.verify(:eddsa, nil, data, signature, [pubkey, :ed448])

  # header stuff #
  defp gen_header(alg, kid, jmod) do
    %{alg: Map.get(@sign_alg_to_header_alg, alg), typ: "JWT", kid: kid}
    |> jmod.encode!()
    |> url_encode()
  end

  defp to_map(encoded, json_mod) do
    with {_, {:ok, json}} <- {:enc, url_decode(encoded)},
         {:ok, payload} <- json_mod.decode(json) do
      {:ok, payload}
    else
      {:enc, _} -> {:error, "encoding invalid"}
      _ -> {:error, "json invalid"}
    end
  end

  defp process_header(header, json_mod) do
    with {:ok, payload} <- to_map(header, json_mod),
         {_, %{"alg" => alg}} <- {:payload, payload} do
      {:ok, Map.get(payload, "kid", "kid_not_set.#{alg}")}
    else
      {:payload, _} -> {:error, "malformed header"}
      error -> error
    end
  end
end
