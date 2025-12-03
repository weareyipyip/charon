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
    - `:signing_key` (optional, default "default"). The ID of the key in the keyset that is used to sign new tokens. To change the signing key at runtime, create a new config using `from_enum/1`; do not modify the struct directly.
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

  # strings whose lengths are multiples of 3 can be pre-encoded and concatenated
  # hseg = header segment
  @hseg0 ~s({"alg") |> len_check_url_enc()
  @hseg1_s256 ~s(:"HS256",) |> len_check_url_enc()
  @hseg1_s384 ~s(:"HS384",) |> len_check_url_enc()
  @hseg1_s512 ~s(:"HS512",) |> len_check_url_enc()
  @hseg1_eddsa ~s(:"EdDSA",) |> len_check_url_enc()
  @hseg2 ~s("typ":"JWT","kid":) |> len_check_url_enc()
  @hseg1_p1305 ~s(:"Poly1305",) |> len_check_url_enc()
  @hseg2_p1305 ~s("typ":"JWT","nonce":") |> len_check_url_enc()
  @hseg3_p1305 ~s("kid":) |> len_check_url_enc()

  @hdr_s256_h @hseg0 <> @hseg1_s256 <> @hseg2
  @hdr_s384_h @hseg0 <> @hseg1_s384 <> @hseg2
  @hdr_s512_h @hseg0 <> @hseg1_s512 <> @hseg2
  @hdr_eddsa_h @hseg0 <> @hseg1_eddsa <> @hseg2
  @p1305_h @hseg0 <> @hseg1_p1305 <> @hseg2_p1305

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
    %{get_keyset: get_keyset, signing_key: {kid, header_tail}} = mod_conf

    with {:ok, _key = {alg, secret}} <- config |> get_keyset.() |> get_key(kid) do
      enc_payload = payload |> jmod.encode!() |> url_encode()
      nonce = new_p1305_nonce(alg, mod_conf)
      key = {alg, gen_otk_if_nonce(secret, nonce)}
      header = create_header(alg, header_tail, nonce)
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
    # if we signed the token ourselves, the header will have a fixed b64-encoded pattern
    # which we can use to fast-track verification without b64/json-decoding the whole thing
    maybe_fast_s1(token, config)
  end

  @compile {:inline, maybe_fast_s1: 2}
  # match {"alg" or leave the fast path
  defp maybe_fast_s1(tok = @hseg0 <> tail, config), do: maybe_fast_s2(tail, tok, config)
  defp maybe_fast_s1(token, config), do: slow_verify(token, config, get_mod_config(config))

  @compile {:inline, maybe_fast_s2: 3}
  # match :"<alg>", or leave the fast path (the poly1305 fast path is separate from here)
  defp maybe_fast_s2(@hseg1_s256 <> tail, tok, c), do: maybe_fast_s3(:s256, tail, tok, c)
  defp maybe_fast_s2(@hseg1_p1305 <> tail, tok, c), do: maybe_fast_s3_p1305(tail, tok, c)
  defp maybe_fast_s2(@hseg1_s384 <> tail, tok, c), do: maybe_fast_s3(:s384, tail, tok, c)
  defp maybe_fast_s2(@hseg1_s512 <> tail, tok, c), do: maybe_fast_s3(:s512, tail, tok, c)
  defp maybe_fast_s2(@hseg1_eddsa <> tail, tok, c), do: maybe_fast_s3(:eddsa, tail, tok, c)
  defp maybe_fast_s2(_, token, config), do: slow_verify(token, config, get_mod_config(config))

  # match "typ":"JWT","kid":"<kid>"} and definitively enter fast path or leave the fast path
  defp maybe_fast_s3(alg, tail, token, config) do
    mconf = get_mod_config(config)
    {kid, htail} = mconf.signing_key

    case tail do
      <<@hseg2, ^htail::binary, ?., enc_pl_and_sig::binary>> ->
        # the header is recognized; reconstruct it from the header tail for fast-track verification
        case alg do
          :s256 -> [@hdr_s256_h, htail]
          :s384 -> [@hdr_s384_h, htail]
          :s512 -> [@hdr_s512_h, htail]
          :eddsa -> [@hdr_eddsa_h, htail]
        end
        |> fast_verify(enc_pl_and_sig, kid, config, mconf)

      _ ->
        slow_verify(token, config, mconf)
    end
  end

  # match "typ":"JWT","nonce":"<nonce>","kid":"<kid>"} and definitively enter poly1305 fast path or leave the fast path
  defp maybe_fast_s3_p1305(tail, token, config) do
    mconf = get_mod_config(config)
    {kid, htail} = mconf.signing_key

    case tail do
      <<@hseg2_p1305, nonce_seg::binary-24, @hseg3_p1305, ^htail::bits, ?., enc_pl_and_sig::bits>> ->
        [@p1305_h, nonce_seg, @hseg3_p1305, htail]
        |> fast_p1305_verify(nonce_seg, enc_pl_and_sig, kid, config, mconf)

      _ ->
        slow_verify(token, config, mconf)
    end
  end

  @compile {:inline, fast_verify: 5}
  # fast path verification for non-poly1305 algs
  defp fast_verify(enc_header, pl_and_sig, kid, config, mod_conf) do
    with {:ok, key = {alg, _}} <-
           config |> mod_conf.get_keyset.() |> get_key(kid),
         sig_len = alg_to_sig_len(alg),
         payload_len = byte_size(pl_and_sig) - sig_len - 1,
         <<enc_pl::binary-size(payload_len), ?., enc_sig::binary-size(sig_len)>> <- pl_and_sig do
      shared_verify(enc_header, enc_pl, enc_sig, key, config.json_module)
    else
      error = {:error, _msg} -> error
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

  @compile {:inline, fast_p1305_verify: 6}
  # fast path verification for poly1305
  @p1305_sig_len 22
  defp fast_p1305_verify(enc_header, nonce_seg, pl_and_sig, kid, config, mod_conf) do
    with payload_len = byte_size(pl_and_sig) - @p1305_sig_len - 1,
         <<enc_pl::binary-size(payload_len), ?., enc_sig::binary-@p1305_sig_len>> <- pl_and_sig,
         {:ok, <<enc_nonce::binary-16, ~s(",)>>} <- url_decode(nonce_seg),
         {:ok, nonce} <- url_decode(enc_nonce),
         {:ok, {_, secret}} <- config |> mod_conf.get_keyset.() |> get_key(kid),
         otk = gen_otk(secret, nonce) do
      shared_verify(enc_header, enc_pl, enc_sig, {:poly1305, otk}, config.json_module)
    else
      error = {:error, _msg} -> error
      _ -> {:error, "malformed token"}
    end
  end

  # the fallback slow path verification that fully decodes the header json
  defp slow_verify(token, config, mod_conf) do
    jmod = config.json_module

    with [enc_header, enc_pl, enc_sig] <- dot_split(token, parts: 3),
         {:ok, payload} <- url_json_decode(enc_header, jmod),
         {:ok, alg} <- get_header_alg(payload),
         kid = get_header_kid(payload, alg),
         {:ok, nonce} <- maybe_get_header_nonce(payload, alg),
         {:ok, {alg, secret}} <- config |> mod_conf.get_keyset.() |> get_key(kid),
         key = {alg, gen_otk_if_nonce(secret, nonce)} do
      shared_verify(enc_header, enc_pl, enc_sig, key, jmod)
    else
      error = {:error, _msg} -> error
      _ -> {:error, "malformed token"}
    end
  end

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

  @compile {:inline, new_p1305_nonce: 2}
  defp new_p1305_nonce(:poly1305, mod_conf) do
    case mod_conf.gen_poly1305_nonce do
      :random -> :crypto.strong_rand_bytes(12)
      function -> function.()
    end
  end

  defp new_p1305_nonce(_, _), do: nil

  @compile {:inline, create_header: 3}
  @doc false
  def create_header(:hmac_sha256, header_tail, _), do: [@hdr_s256_h, header_tail]

  def create_header(:poly1305, header_tail, nonce) do
    [@p1305_h, url_encode(~s(#{url_encode(nonce)}",)), @hseg3_p1305, header_tail]
  end

  def create_header(:hmac_sha384, header_tail, _), do: [@hdr_s384_h, header_tail]
  def create_header(:hmac_sha512, header_tail, _), do: [@hdr_s512_h, header_tail]
  def create_header(:eddsa_ed25519, header_tail, _), do: [@hdr_eddsa_h, header_tail]
  def create_header(:eddsa_ed448, header_tail, _), do: [@hdr_eddsa_h, header_tail]

  defp url_json_decode(encoded, json_mod) do
    with {_, {:ok, json}} <- {:enc, url_decode(encoded)},
         {:ok, payload} <- json_mod.decode(json) do
      {:ok, payload}
    else
      {:enc, _} -> {:error, "encoding invalid"}
      _ -> {:error, "json invalid"}
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

  @compile {:inline, gen_otk_if_nonce: 2}
  defp gen_otk_if_nonce(secret, nil), do: secret
  defp gen_otk_if_nonce(secret, nonce), do: gen_otk(secret, nonce)

  @compile {:inline, gen_otk: 2}
  defp gen_otk(secret, nonce) do
    # after https://github.com/potatosalad/erlang-jose/blob/main/src/jwa/chacha20_poly1305/jose_chacha20_poly1305_crypto.erl#L58
    :crypto.crypto_one_time(:chacha20, secret, <<0::32, nonce::binary>>, <<0::256>>, true)
  end
end
