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
  For that reason, no two keys should have the same kid.

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
    - `:get_keyset` (optional, default `default_keyset/1`). The keyset used to sign and verify JWTs. If not specified, a default keyset with a single key called "default" is used, which is derived from Charon's base secret. You should never use the same ID for different keys.
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
  require PersistentTermCache.Macro

  @behaviour Charon.TokenFactory.Behaviour

  # strings whose lengths are multiples of 3 can be pre-encoded and concatenated
  @p1305_h ~s({"alg":"Poly1305","typ":"JWT","nonce":") |> len_check_url_enc()
  @p1305_kid_seg ~s("kid":) |> len_check_url_enc()

  @type hmac_alg :: :hmac_sha256 | :hmac_sha384 | :hmac_sha512
  @type eddsa_alg :: :eddsa_ed25519 | :eddsa_ed448
  @type mac_alg :: :poly1305
  @type eddsa_keypair :: {eddsa_alg(), {binary(), binary()}}
  @type symmetric_key :: {hmac_alg() | mac_alg(), binary()}
  @type key :: symmetric_key() | eddsa_keypair()
  @type keyset :: %{required(String.t()) => key()}

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
    base_secret = config.get_base_secret.()
    default_key = KeyGenerator.derive_key(base_secret, "charon_jwt_default", log: false)
    %{"default" => {_default_alg = :hmac_sha256, default_key}}
  end

  ########
  # Sign #
  ########

  @impl true
  def sign(payload, config) do
    mod_conf = get_mod_config(config)

    init_keyset(config, mod_conf)
    |> case do
      {:fixed_hdr, header, key, _keyset} ->
        {header, key}

      {:poly1305 = alg, header_tail, secret, _keyset} ->
        nonce =
          case mod_conf.gen_poly1305_nonce do
            :random -> :crypto.strong_rand_bytes(12)
            function -> function.()
          end

        key = {alg, gen_otk(secret, nonce)}
        header = [@p1305_h, url_encode(~s(#{url_encode(nonce)}",)), @p1305_kid_seg, header_tail]
        {header, key}

      error ->
        error
    end
    |> create_token(payload, config)
  end

  @compile {:inline, create_token: 3}
  defp create_token({header, key}, payload, config) do
    enc_payload = payload |> config.json_module.encode!() |> url_encode()
    data = [header, ?., enc_payload]
    signature = data |> do_sign(key) |> url_encode()
    token = [data, ?., signature] |> IO.iodata_to_binary()
    {:ok, token}
  end

  defp create_token(error, _, _), do: error

  defp do_sign(data, {:hmac_sha256, key}), do: calc_hmac(data, key, :sha256)
  defp do_sign(data, {:poly1305, otk}), do: :crypto.mac(:poly1305, otk, data)
  defp do_sign(data, {:hmac_sha384, key}), do: calc_hmac(data, key, :sha384)
  defp do_sign(data, {:hmac_sha512, key}), do: calc_hmac(data, key, :sha512)

  defp do_sign(data, {:eddsa_ed25519, {_, privkey}}),
    do: :crypto.sign(:eddsa, :none, data, [privkey, :ed25519])

  defp do_sign(data, {:eddsa_ed448, {_, privkey}}),
    do: :crypto.sign(:eddsa, :none, data, [privkey, :ed448])

  ##########
  # Verify #
  ##########

  @impl true
  def verify(token, config) do
    mod_conf = get_mod_config(config)
    init_keyset(config, mod_conf) |> maybe_fast_verify(token, config)
  end

  ###############
  # Fast verify #
  ###############

  # if we signed the token ourselves, the header will have a fixed b64-encoded pattern
  # which we can use to fast-track verification without b64/json-decoding the whole thing
  @compile {:inline, maybe_fast_verify: 3}
  defp maybe_fast_verify(init_keyset, token, config)

  defp maybe_fast_verify({:fixed_hdr, hdr, key, keyset}, token, config) do
    case token do
      <<^hdr::binary, ?., pl_and_sig::binary>> -> fast_verify(hdr, pl_and_sig, key, config)
      _ -> slow_verify(token, keyset, config)
    end
  end

  defp maybe_fast_verify({:poly1305, exp_htail, secret, keyset}, token, config) do
    case token do
      <<@p1305_h, nonce_seg::binary-24, @p1305_kid_seg, ^exp_htail::bits, ?.,
        enc_pl_and_sig::bits>> ->
        [@p1305_h, nonce_seg, @p1305_kid_seg, exp_htail]
        |> fast_p1305_verify(nonce_seg, enc_pl_and_sig, secret, config)

      _ ->
        slow_verify(token, keyset, config)
    end
  end

  # if the signing key is not found, verification could still work with one of the other keys
  defp maybe_fast_verify({:key_not_found, keyset}, token, config) do
    slow_verify(token, keyset, config)
  end

  @compile {:inline, fast_verify: 4}
  # fast path verification for non-poly1305 algs
  defp fast_verify(enc_header, pl_and_sig, key = {alg, _}, config) do
    with sig_len = alg_to_sig_len(alg),
         payload_len = byte_size(pl_and_sig) - sig_len - 1,
         <<enc_pl::binary-size(payload_len), ?., enc_sig::binary-size(sig_len)>> <- pl_and_sig do
      shared_verify(enc_header, enc_pl, enc_sig, key, config.json_module)
    else
      _ -> {:error, "malformed token"}
    end
  end

  @compile {:inline, alg_to_sig_len: 1}
  defp alg_to_sig_len(alg)
  defp alg_to_sig_len(:hmac_sha256), do: 43
  defp alg_to_sig_len(:hmac_sha384), do: 64
  defp alg_to_sig_len(:hmac_sha512), do: 86
  defp alg_to_sig_len(:eddsa_ed25519), do: 86
  defp alg_to_sig_len(:eddsa_ed448), do: 152

  @compile {:inline, fast_p1305_verify: 5}
  # fast path verification for poly1305
  @p1305_sig_len 22
  defp fast_p1305_verify(enc_header, nonce_seg, pl_and_sig, secret, config) do
    with payload_len = byte_size(pl_and_sig) - @p1305_sig_len - 1,
         <<enc_pl::binary-size(payload_len), ?., enc_sig::binary-@p1305_sig_len>> <- pl_and_sig,
         {:ok, <<enc_nonce::binary-16, ~s(",)>>} <- url_decode(nonce_seg),
         {:ok, nonce} <- url_decode(enc_nonce),
         otk = gen_otk(secret, nonce) do
      shared_verify(enc_header, enc_pl, enc_sig, {:poly1305, otk}, config.json_module)
    else
      _ -> {:error, "malformed token"}
    end
  end

  ###############
  # Slow verify #
  ###############

  # the fallback slow path verification that fully decodes the header json
  defp slow_verify(token, keyset, config) do
    jmod = config.json_module

    with [enc_header, enc_pl, enc_sig] <- dot_split(token, parts: 3),
         {:ok, hdr_payload} <- url_json_decode(enc_header, jmod),
         {:ok, hdr_alg_claim} <- get_header_alg(hdr_payload),
         kid = get_header_kid(hdr_payload, hdr_alg_claim),
         {:ok, key} <- get_key(keyset, kid),
         {:ok, token_key} <- resolve_token_key(hdr_payload, key) do
      shared_verify(enc_header, enc_pl, enc_sig, token_key, jmod)
    else
      error = {:error, _msg} -> error
      _ -> {:error, "malformed token"}
    end
  end

  @compile {:inline, get_header_alg: 1}
  defp get_header_alg(_header_pl = %{"alg" => hdr_alg_claim}), do: {:ok, hdr_alg_claim}
  defp get_header_alg(_), do: {:error, "malformed header"}

  @compile {:inline, get_header_kid: 2}
  defp get_header_kid(%{"kid" => kid}, _), do: kid
  defp get_header_kid(_, hdr_alg_claim), do: "kid_not_set.#{hdr_alg_claim}"

  @compile {:inline, resolve_token_key: 2}
  defp resolve_token_key(header_pl, {:poly1305 = p1305, secret}) do
    with %{"nonce" => <<nonce::binary-16>>} <- header_pl,
         {:ok, nonce} <- url_decode(nonce) do
      {:ok, {p1305, gen_otk(secret, nonce)}}
    else
      _ -> {:error, "malformed header"}
    end
  end

  defp resolve_token_key(_, key), do: {:ok, key}

  #################
  # Shared verify #
  #################

  # all verification paths ultimately check the signature here and then decode the payload
  defp shared_verify(enc_header, enc_pl, enc_sig, key, jmod) do
    with {:ok, signature} <- url_decode(enc_sig),
         data = [enc_header, ?., enc_pl],
         true <- do_verify(data, key, signature) or {:error, "signature invalid"},
         res = {:ok, _} <- url_json_decode(enc_pl, jmod) do
      res
    else
      error = {:error, _msg} -> error
      _ -> {:error, "malformed token"}
    end
  end

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

  defp url_json_decode(encoded, json_mod) do
    with {_, {:ok, json}} <- {:enc, url_decode(encoded)},
         {:ok, payload} <- json_mod.decode(json) do
      {:ok, payload}
    else
      {:enc, _} -> {:error, "encoding invalid"}
      _ -> {:error, "json invalid"}
    end
  end

  ##########
  # Keyset #
  ##########
  defp init_keyset(config, mod_conf = %{signing_key: kid}) do
    PersistentTermCache.Macro.get_or_create {__MODULE__, kid} do
      keyset = mod_conf.get_keyset.(config)

      case get_key(keyset, kid) do
        {:ok, {:poly1305, secret}} ->
          header_tail = url_encode(~s("#{kid}"}))
          {:poly1305, header_tail, secret, keyset}

        {:ok, key = {alg, _}} ->
          expected_header =
            case alg do
              :hmac_sha256 -> "HS256"
              :hmac_sha384 -> "HS384"
              :hmac_sha512 -> "HS512"
              :eddsa_ed25519 -> "EdDSA"
              :eddsa_ed448 -> "EdDSA"
            end
            |> then(fn alg -> ~s({"alg":"#{alg}","typ":"JWT","kid":"#{kid}"}) |> url_encode() end)

          {:fixed_hdr, expected_header, key, keyset}

        _ ->
          {:key_not_found, keyset}
      end
    end
  end

  @compile {:inline, get_key: 2}
  defp get_key(keyset, kid) do
    case keyset do
      %{^kid => key} -> {:ok, key}
      _ -> {:error, "key not found"}
    end
  end

  ###########
  # Helpers #
  ###########

  @compile {:inline, calc_hmac: 3}
  defp calc_hmac(data, key, alg), do: :crypto.mac(:hmac, alg, key, data)

  @compile {:inline, gen_otk: 2}
  defp gen_otk(secret, nonce) do
    # after https://github.com/potatosalad/erlang-jose/blob/main/src/jwa/chacha20_poly1305/jose_chacha20_poly1305_crypto.erl#L58
    :crypto.crypto_one_time(:chacha20, secret, <<0::32, nonce::binary>>, <<0::256>>, true)
  end
end
