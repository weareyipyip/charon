defmodule Charon.TokenFactory.SymmetricJwt do
  @moduledoc """
  The default and most simple form of self-signed tokens,
  JWTs with symmetric-key signatures.
  These are suited for everything but OpenID Connect implementations,
  because these require third parties to verify the token signature,
  which requires assymetric keys.

  ## Config

  Additional config is required for this module:

      Charon.Config.from_enum(
        ...,
        optional_modules: %{
          Charon.TokenFactory.SymmetricJwt => %{
            get_secret: fn -> :crypto.strong_rand_bytes(32) end,
            algorithm: :poly1305
          }
        }
      )

  The following options are supported:
    - `:get_secret` (required). A getter/0 for secret for the JWT's signature algorithm. Must be exactly 256 bits in case of Poly1305 alg.
    - `:algorithm` (optional). The token signature algorithm, may be `:sha256` (default), `:sha384`, `:sha512` or `:poly1305`.

  ## Examples / doctests

      # verify ignores the config's algorithm, grabbing it from the JWT header instead
      # this allows changing algorithms without invalidating existing JWTs
      iex> get_secret = fn -> "symmetric key" end
      iex> config = %{optional_modules: %{SymmetricJwt => SymmetricJwt.Config.from_enum(get_secret: get_secret)}}
      iex> payload = %{"iss" => "joe", "exp" => 1_300_819_380, "http://example.com/is_root" => true}
      iex> {:ok, token} = sign(payload, config)
      {:ok, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.shLcxOl_HBBsOTvPnskfIlxHUibPN7Y9T4LhPB-iBwM"}
      iex> config = %{optional_modules: %{SymmetricJwt => SymmetricJwt.Config.from_enum(get_secret: get_secret, algorithm: :sha512)}}
      iex> {:ok, ^payload} = verify(token, config)

      iex> get_secret = fn -> "symmetric key" end
      iex> config = %{optional_modules: %{SymmetricJwt => %{get_secret: get_secret}}}
      iex> verify("a", config)
      {:error, "malformed token"}
      iex> verify("a.b.c", config)
      {:error, "encoding invalid"}
      iex> header = %{"alg" => "boom"} |> Jason.encode!() |> Base.url_encode64(padding: false)
      iex> verify(header <> ".YQ.YQ", config)
      {:error, "unsupported signature algorithm"}
      iex> header = %{"alg" => "HS256"} |> Jason.encode!() |> Base.url_encode64(padding: false)
      iex> verify(header <> ".YQ.YQ", config)
      {:error, "signature invalid"}

      # poly1305 is also supported, and requires a 256-bits key
      iex> secret = :crypto.strong_rand_bytes(32)
      iex> get_secret = fn -> secret end
      iex> config = %{optional_modules: %{SymmetricJwt => %{get_secret: get_secret, algorithm: :poly1305}}}
      iex> payload = %{"iss" => "joe", "exp" => 1_300_819_380, "http://example.com/is_root" => true}
      iex> {:ok, token} = sign(payload, config)
      iex> {:ok, ^payload} = verify(token, config)
      iex> header = token |> String.split(".") |> List.first() |> Base.url_decode64!() |> Jason.decode!()
      iex> %{"alg" => "Poly1305", "nonce" => <<_::binary>>, "typ" => "JWT"} = header
      iex> config = %{optional_modules: %{SymmetricJwt => SymmetricJwt.Config.from_enum(get_secret: fn -> :crypto.strong_rand_bytes(32) end)}}
      iex> {:error, "signature invalid"} = verify(token, config)
  """
  @behaviour Charon.TokenFactory
  alias Charon.Internal

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
    %{algorithm: alg, get_secret: get_secret} = get_module_config(config)
    secret = get_secret.()

    with {:ok, json_payload} <- Jason.encode(payload) do
      payload = url_encode(json_payload)
      mac_base = [generate_header(alg), ?., payload]
      mac = mac_base |> calc_mac(secret, alg) |> url_encode()
      token = [mac_base, ?., mac] |> IO.iodata_to_binary()
      {:ok, token}
    else
      _ -> {:error, "could not encode payload"}
    end
  end

  @impl true
  def verify(token, config) do
    %{get_secret: get_secret} = get_module_config(config)
    secret = get_secret.()

    with [header, payload, signature] <- String.split(token, ".", parts: 3),
         {:ok, alg} <- get_signature_algorithm(header),
         mac_base = [header, ?., payload],
         mac = calc_mac(mac_base, secret, alg),
         {:ok, signature} <- url_decode(signature),
         true <- Plug.Crypto.secure_compare(mac, signature),
         {:ok, payload} <- to_map(payload) do
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

  @compile {:inline, get_module_config: 1}
  defp get_module_config(%{optional_modules: %{__MODULE__ => config}}), do: config

  defp url_encode(bin), do: Base.url_encode64(bin, @encoding_opts)
  defp url_decode(bin), do: Base.url_decode64(bin, @encoding_opts)

  defp generate_header(alg) do
    %{alg: Map.get(@alg_to_header_map, alg), typ: "JWT"}
    |> maybe_add_nonce(alg)
    |> Jason.encode!()
    |> Base.url_encode64(@encoding_opts)
  end

  defp maybe_add_nonce(header, :poly1305),
    do: Map.put(header, :nonce, Internal.random_url_encoded(16))

  defp maybe_add_nonce(header, _), do: header

  defp calc_mac(data, secret, :poly1305), do: :crypto.mac(:poly1305, secret, data)
  defp calc_mac(data, secret, alg), do: :crypto.mac(:hmac, alg, secret, data)

  defp to_map(encoded) do
    with {:ok, json} <- url_decode(encoded),
         {:ok, payload} <- Jason.decode(json) do
      {:ok, payload}
    else
      :error -> {:error, "encoding invalid"}
      error -> error
    end
  end

  defp get_signature_algorithm(header) do
    with {:ok, payload} <- to_map(header),
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
