defmodule Charon.TokenFactory.FastJwt do
  @moduledoc """
  A compile-time optimized JWT token factory for maximum performance.

  This module generates a specialized token factory at compile time,
  with the signing algorithm, key ID, and header pre-computed as binary constants.
  This eliminates runtime overhead from dynamic dispatch and header construction,
  resulting in significantly faster token signing and verification.

  For detailed information about keysets, algorithms, and configuration options,
  see `Charon.TokenFactory.Jwt`.

  > #### Experimental {: .warning}
  >
  > This is an experimental module. It is tested, and the performance improvements work out,
  > but it is less foolproof than its regular sibling. You must be careful that you use a signing
  > key at runtime with the same ID but a different value than at compile time.
  > This should be the case if you use `Charon.TokenFactory.Jwt.default_keyset/1`.
  > Use at your own risk.

  ## How it works

  Unlike `Charon.TokenFactory.Jwt`, which resolves the signing key and algorithm at runtime,
  this module uses macros to "bake in" the configuration at compile time:

    - The `get_keyset` function, signing key ID, and algorithm are read at compile time
    - The JWT header is pre-encoded as a binary constant
    - The signature length is pre-computed based on the algorithm
    - Pattern matching on the header prefix enables fast verification
    - Algorithm-specific signing/verification functions are generated inline

  The actual key material is still fetched at runtime via `get_keyset`, allowing for
  runtime key rotation without recompilation (as long as the key ID and algorithm remain the same).

  Tokens that don't match the expected header format (e.g., tokens signed with a different
  key or algorithm) fall back to `Charon.TokenFactory.Jwt.verify/2` for verification,
  ensuring backward compatibility with key rotation.

  ## Trade-offs

    - **Pro**: Faster signing and verification for the configured signing key
    - **Pro**: Reduced memory allocations from pre-computed headers
    - **Con**: Requires recompilation when changing the signing key ID or algorithm
    - **Con**: The `get_keyset` function, signing key ID, and algorithm must be known at compile time
      (the actual key material can change at runtime).

  ## Usage

  Define a module that uses `FastJwt` with your Charon configuration:

      defmodule MyApp.FastTokenFactory do
        use Charon.TokenFactory.FastJwt, config: MyApp.Charon.config()
      end

  The `:config` option must be a `Charon.Config` struct available at compile time.
  This module uses the same configuration as `Charon.TokenFactory.Jwt`, and its options must be set using `Charon.TokenFactory.Jwt` as the key of the `:optional_modules` map the Charon config.
  The module will implement the `Charon.TokenFactory.Behaviour` and can be used
  directly in your application:

      # Sign a token
      {:ok, token} = MyApp.FastTokenFactory.sign(%{"user_id" => 123}, config)

      # Verify a token
      {:ok, payload} = MyApp.FastTokenFactory.verify(token, config)
  """
  alias Charon.TokenFactory.Jwt
  import Charon.Internal

  @doc false
  # add padding spaces in the json so that the total length is a multiple of 3
  # this results in a base64-encoded binary to which another base64-encoded string
  # can be appended without breaking the encoding of the whole
  def gen_static_poly1305_header_head(kid, jmod) do
    base_head = ~s({"alg":"Poly1305","typ":"JWT","kid":#{jmod.encode!(kid)},"nonce":)

    case base_head |> byte_size() |> rem(3) do
      0 -> base_head <> ~s(  ")
      1 -> base_head <> ~s( ")
      2 -> base_head <> ~s(")
    end
    |> url_encode()
  end

  defmacro __using__(opts \\ []) do
    quote bind_quoted: [opts: opts], location: :keep do
      import Jwt.Config, only: [get_mod_config: 1]
      import Charon.Internal
      import Charon.Internal.Crypto
      @behaviour Charon.TokenFactory.Behaviour

      config = opts[:config]
      %Charon.Config{} = config
      jwt_mod_conf = get_mod_config(config)
      %Jwt.Config{signing_key: signing_kid, get_keyset: get_keyset} = jwt_mod_conf
      {alg, _} = get_keyset.(config) |> Map.fetch!(signing_kid)

      @jmod config.json_module
      @get_keyset get_keyset
      @signing_alg alg
      @signing_kid signing_kid
      @gen_nonce jwt_mod_conf.gen_poly1305_nonce

      if @signing_alg == :poly1305 do
        @header_h Charon.TokenFactory.FastJwt.gen_static_poly1305_header_head(@signing_kid, @jmod)
        @enc_nonce_example url_encode(<<0::96>>)
        @enc_nonce_length byte_size(@enc_nonce_example)
        @header_t_example url_encode(~s(#{@enc_nonce_example}"}))
        @rem_header_bytes byte_size(@header_t_example)
        @sig_len 22

        @impl true
        def sign(payload, config) do
          case @get_keyset.(config) |> get_key() do
            {:ok, {_, secret}} ->
              enc_payload = @jmod.encode!(payload) |> url_encode()
              nonce = new_poly1305_nonce()
              data = [@header_h, url_encode(~s(#{url_encode(nonce)}"})), ?., enc_payload]
              otk = gen_otk_for_nonce(secret, nonce)
              signature = :crypto.mac(:poly1305, otk, data) |> url_encode()
              token = [data, ?., signature] |> IO.iodata_to_binary()
              {:ok, token}

            _ ->
              {:error, "could not create jwt"}
          end
        end

        @impl true
        def verify(
              <<@header_h, header_t::binary-@rem_header_bytes, ?., pl_and_sig::binary>>,
              config
            ) do
          payload_len = byte_size(pl_and_sig) - @sig_len - 1

          with <<payload::binary-size(payload_len), ?., signature::binary-size(@sig_len)>> <-
                 pl_and_sig,
               {:ok, <<nonce::binary-@enc_nonce_length, ~s("})>>} <- url_decode(header_t),
               {:ok, nonce} <- url_decode(nonce),
               {:ok, {_, secret}} <- @get_keyset.(config) |> get_key(),
               {:ok, signature} <- url_decode(signature),
               otk = gen_otk_for_nonce(secret, nonce),
               data = [@header_h, header_t, ?., payload],
               valid? = :crypto.mac(:poly1305, otk, data) |> constant_time_compare(signature),
               {_, true} <- {:signature_valid, valid?},
               {:ok, payload} <- url_decode(payload),
               res = {:ok, payload} <- @jmod.decode(payload) do
            res
          else
            {:signature_valid, _} -> {:error, "signature invalid"}
            error = {:error, _msg} -> error
            _ -> {:error, "malformed token"}
          end
        end

        def verify(token, config), do: Jwt.verify(token, config)

        @compile {:inline, new_poly1305_nonce: 0}
        if @gen_nonce == :random do
          defp new_poly1305_nonce, do: :crypto.strong_rand_bytes(12)
        else
          defp new_poly1305_nonce, do: @gen_nonce.()
        end

        @compile {:inline, gen_otk_for_nonce: 2}
        defp gen_otk_for_nonce(secret, nonce) do
          # after https://github.com/potatosalad/erlang-jose/blob/main/src/jwa/chacha20_poly1305/jose_chacha20_poly1305_crypto.erl#L58
          :crypto.crypto_one_time(:chacha20, secret, <<0::32, nonce::binary>>, <<0::256>>, true)
        end
      else
        @header [Jwt.create_header(@signing_alg, @signing_kid, nil), ?.] |> IO.iodata_to_binary()
        @sig_len (case @signing_alg do
                    :hmac_sha256 -> 43
                    :hmac_sha384 -> 64
                    :hmac_sha512 -> 86
                    :eddsa_ed25519 -> 86
                    :eddsa_ed448 -> 152
                  end)

        @impl true
        def sign(payload, config) do
          case @get_keyset.(config) |> get_key() do
            {:ok, {_, secret}} ->
              enc_payload = @jmod.encode!(payload) |> url_encode()
              data = [@header, enc_payload]
              signature = data |> do_sign(secret) |> url_encode()
              token = [data, ?., signature] |> IO.iodata_to_binary()
              {:ok, token}

            _ ->
              {:error, "could not create jwt"}
          end
        end

        @impl true
        def verify(<<@header, payload_and_sig::binary>>, config) do
          payload_len = byte_size(payload_and_sig) - @sig_len - 1

          with <<payload::binary-size(payload_len), ?., signature::binary-size(@sig_len)>> <-
                 payload_and_sig,
               {:ok, signature} <- url_decode(signature),
               {:ok, {_, secret}} <- @get_keyset.(config) |> get_key(),
               {_, true} <- {:signature_valid, do_verify([@header, payload], secret, signature)},
               {:ok, payload} <- url_decode(payload),
               res = {:ok, payload} <- @jmod.decode(payload) do
            res
          else
            {:signature_valid, _} -> {:error, "signature invalid"}
            error = {:error, _msg} -> error
            _ -> {:error, "malformed token"}
          end
        end

        def verify(token, config), do: Jwt.verify(token, config)

        @compile {:inline, do_sign: 2}
        case @signing_alg do
          :hmac_sha256 ->
            defp do_sign(data, key), do: :crypto.mac(:hmac, :sha256, key, data)

          :hmac_sha384 ->
            defp do_sign(data, key), do: :crypto.mac(:hmac, :sha384, key, data)

          :hmac_sha512 ->
            defp do_sign(data, key), do: :crypto.mac(:hmac, :sha512, key, data)

          :eddsa_ed25519 ->
            defp do_sign(data, {_, privkey}),
              do: :crypto.sign(:eddsa, :none, data, [privkey, :ed25519])

          :eddsa_ed448 ->
            defp do_sign(data, {_, privkey}),
              do: :crypto.sign(:eddsa, :none, data, [privkey, :ed448])
        end

        @compile {:inline, do_verify: 3}
        case @signing_alg do
          :hmac_sha256 ->
            defp do_verify(data, key, signature),
              do: :crypto.mac(:hmac, :sha256, key, data) |> constant_time_compare(signature)

          :hmac_sha384 ->
            defp do_verify(data, key, signature),
              do: :crypto.mac(:hmac, :sha384, key, data) |> constant_time_compare(signature)

          :hmac_sha512 ->
            defp do_verify(data, key, signature),
              do: :crypto.mac(:hmac, :sha512, key, data) |> constant_time_compare(signature)

          :eddsa_ed25519 ->
            defp do_verify(data, {pubkey, _privkey}, signature),
              do: :crypto.verify(:eddsa, :none, data, signature, [pubkey, :ed25519])

          :eddsa_ed448 ->
            defp do_verify(data, {pubkey, _privkey}, signature),
              do: :crypto.verify(:eddsa, :none, data, signature, [pubkey, :ed448])
        end
      end

      @compile {:inline, get_key: 1}
      defp get_key(%{@signing_kid => key = {@signing_alg, _}}), do: {:ok, key}
      defp get_key(%{@signing_kid => _}), do: raise("sign alg changed between compile/runtime")
      defp get_key(_), do: {:error, "key not found"}
    end
  end
end
