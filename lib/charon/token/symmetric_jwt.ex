defmodule Charon.Token.SymmetricJwt do
  @moduledoc """
  The default and most simple form of self-signed tokens,
  JWTs with symmetric-key signatures.
  These are suited for everything but OpenID Connect implementations,
  because these require third parties to verify the token signature,
  which requires assymetric keys.

  ## Examples / doctests

      iex> key = "symmetric key"
      iex> config = %{token_secret: key, token_algorithm: :sha256}
      iex> payload = %{"iss" => "joe", "exp" => 1_300_819_380, "http://example.com/is_root" => true}
      iex> {:ok, token} = sign(payload, config)
      {:ok, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.shLcxOl_HBBsOTvPnskfIlxHUibPN7Y9T4LhPB-iBwM"}
      iex> {:ok, ^payload} = verify(token, config)

      iex> key = "symmetric key"
      iex> config = %{token_secret: key, token_algorithm: :sha256}
      iex> verify("a", config)
      {:error, "malformed token"}
      iex> verify("a.b.c", config)
      {:error, "encoding invalid"}
      iex> verify("#{%{"alg" => "boom"} |> Jason.encode!() |> Base.url_encode64(padding: false)}.YQ.YQ", config)
      {:error, "unsupported algorithm"}
      iex> verify("#{%{"alg" => "HS256"} |> Jason.encode!() |> Base.url_encode64(padding: false)}.YQ.YQ", config)
      {:error, "signature invalid"}
      iex> verify("#{%{"alg" => "HS256"} |> Jason.encode!() |> Base.url_encode64(padding: false)}.YQ.YQ", config)
      {:error, "signature invalid"}

      # poly1305 is also supported, and requires a 256-bits key
      iex> key = "LhFCsjjaQD0z0MQztnIsIx-1EGXXhIwURGhPkab4AYk" |> Base.url_decode64!(padding: false)
      iex> config = %{token_secret: key, token_algorithm: :poly1305}
      iex> payload = %{"iss" => "joe", "exp" => 1_300_819_380, "http://example.com/is_root" => true}
      iex> {:ok, token} = sign(payload, config)
      iex> {:ok, ^payload} = verify(token, config)
      iex> header = token |> String.split(".") |> List.first() |> Base.url_decode64!() |> Jason.decode!()
      iex> %{"alg" => "Poly1305", "nonce" => <<_::binary>>, "typ" => "JWT"} = header
      iex> {:error, "signature invalid"} = verify(token <> "a", config)
  """
  @behaviour Charon.Token

  @encoding_opts padding: false
  @sha256_header %{"alg" => "HS256", "typ" => "JWT"}
                 |> Jason.encode!()
                 |> Base.url_encode64(@encoding_opts)

  @impl true
  def sign(payload, config) do
    with {:ok, json_payload} <- Jason.encode(payload) do
      payload = url_encode(json_payload)
      mac_base = [generate_header(config.token_algorithm), ?., payload]
      mac = mac_base |> calc_mac(config) |> url_encode()
      token = [mac_base, ?., mac] |> IO.iodata_to_binary()
      {:ok, token}
    else
      _ -> {:error, "could not encode payload"}
    end
  end

  @impl true
  def verify(token, config) do
    with [header, payload, signature] <- String.split(token, ".", parts: 3),
         :ok <- verify_header(header),
         mac_base = [header, ?., payload],
         mac = calc_mac(mac_base, config),
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

  ###########
  # Private #
  ###########

  defp url_encode(bin), do: Base.url_encode64(bin, @encoding_opts)
  defp url_decode(bin), do: Base.url_decode64(bin, @encoding_opts)

  defp generate_header(:sha256), do: @sha256_header

  defp generate_header(:poly1305) do
    %{
      "alg" => "Poly1305",
      "typ" => "JWT",
      # poly1305 needs a nonce
      "nonce" => :crypto.strong_rand_bytes(16) |> url_encode()
    }
    |> Jason.encode!()
    |> url_encode()
  end

  defp calc_mac(data, config = %{token_algorithm: :poly1305}),
    do: :crypto.mac(:poly1305, config.token_secret, data)

  defp calc_mac(data, config), do: :crypto.mac(:hmac, :sha256, config.token_secret, data)

  defp to_map(encoded) do
    with {:ok, json} <- url_decode(encoded),
         {:ok, payload} <- Jason.decode(json) do
      {:ok, payload}
    else
      :error -> {:error, "encoding invalid"}
      error -> error
    end
  end

  defp verify_header(header) do
    with {:ok, payload} <- to_map(header),
         %{"alg" => alg} <- payload,
         true <- alg in ~w(HS256 Poly1305) do
      :ok
    else
      %{} -> {:error, "malformed header"}
      false -> {:error, "unsupported algorithm"}
      error -> error
    end
  end
end
