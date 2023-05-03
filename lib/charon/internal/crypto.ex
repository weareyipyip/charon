defmodule Charon.Internal.Crypto do
  @moduledoc false
  import Charon.Internal

  # this ensures function_exported/3 works for this module
  Code.ensure_loaded(:crypto)

  @encr_alg :chacha20
  @hmac_alg :sha256
  @iv_size 16

  @doc """
  Encrypt the plaintext into a binary using the provided key.
  """
  @spec encrypt(binary, binary) :: binary
  def encrypt(plaintext, key) do
    iv = :crypto.strong_rand_bytes(@iv_size)
    # prefix a zero byte to detect decryption failure
    # because it is only one byte there is a chance of failed decryption not being detected
    # this is acceptable because it will fail really often and be quite clear from all the crashes
    prefixed_plaintext = [0 | plaintext]
    encrypted = :crypto.crypto_one_time(@encr_alg, key, iv, prefixed_plaintext, true)
    <<iv::binary, encrypted::binary>>
  end

  @doc """
  Decrypt a binary using the provided key and return the plaintext or an error.
  """
  @spec decrypt(binary, binary) :: {:ok, binary} | {:error, :decryption_failed}
  def decrypt(_encrypted = <<iv::binary-size(@iv_size), ciphertext::binary>>, key) do
    case :crypto.crypto_one_time(@encr_alg, key, iv, ciphertext, false) do
      _prefixed_plaintext = <<0, plaintext::binary>> -> {:ok, plaintext}
      _ -> {:error, :decryption_failed}
    end
  end

  @doc """
  Constant time memory comparison of fixed length binaries, such as results of HMAC computations.
  Binaries of different lengths always return `false`.

  ## Doctests

      iex> constant_time_compare(<<0>>, <<0>>)
      true
      iex> constant_time_compare(<<0>>, <<1>>)
      false
      iex> constant_time_compare(<<1>>, <<1, 2>>)
      false
  """
  @spec constant_time_compare(binary, binary) :: boolean()
  if function_exported?(:crypto, :hash_equals, 2) do
    def constant_time_compare(bin_a, bin_b) do
      byte_size(bin_a) == byte_size(bin_b) and :crypto.hash_equals(bin_a, bin_b)
    end
  else
    def constant_time_compare(bin_a, bin_b), do: Plug.Crypto.secure_compare(bin_a, bin_b)
  end

  @doc """
  Generate a random URL-encoded string of `byte_size` bytes.

  ## Doctests

      iex> random = random_url_encoded(16)
      iex> {:ok, <<_::binary>>} = Base.url_decode64(random, padding: false)
  """
  @spec random_url_encoded(pos_integer()) :: binary
  def random_url_encoded(byte_size) do
    byte_size |> :crypto.strong_rand_bytes() |> url_encode()
  end

  @doc """
  Calculate a HMAC of data using key. The algorithm is #{@hmac_alg}.

  ## Doctests

      iex> <<174, 127, 185, 114, 225, 247, 199, 79, _::binary>> = hmac(["iodata"], "secret")
  """
  @spec hmac(iodata, binary) :: binary
  def hmac(data, key), do: :crypto.mac(:hmac, @hmac_alg, key, data)

  @doc """
  Compare `exp_hmac` with the HMAC of `data` given `key`.

  ## Doctests

      iex> data = ["iodata"]
      iex> hmac = hmac(data, "secret")
      iex> hmac_matches?(data, "secret", hmac)
      true
      iex> hmac_matches?(data, "other secret", hmac)
      false
  """
  @spec hmac_matches?(iodata, binary, binary) :: boolean
  def hmac_matches?(data, key, exp_hmac), do: data |> hmac(key) |> constant_time_compare(exp_hmac)

  @doc """
  Sign a binary into a new binary prefixed with a header containing the original binary's url-encoded HMAC.
  If the input data is a human-readable (UTF-8) string, the result of this function will be too.

  The output format may change, but will still be verifiable by `verify_hmac/2`.

  ## Doctests

      iex> sign_encoded_hmac("charon!", "secret")
      "signed_u64.MwvpgZ_Tb5P19rltHpsHE_ONQs3dR6Et39Adu34WvsU.charon!"
  """
  @spec sign_encoded_hmac(binary, binary) :: binary
  def sign_encoded_hmac(binary, key) do
    hmac = binary |> hmac(key) |> url_encode()
    <<"signed_u64.", hmac::binary, ?., binary::binary>>
  end

  @doc """
  Sign a binary into a new binary prefixed with a header containing the original binary's HMAC.

  The output format may change, but will still be verifiable by `verify_hmac/2`.

  ## Doctests

      iex> <<"signed.", _hmac::256, ".charon!">> = sign_hmac("charon!", "secret")
  """
  @spec sign_hmac(binary, binary) :: binary
  def sign_hmac(binary, key) do
    hmac = hmac(binary, key)
    <<"signed.", hmac::binary, ?., binary::binary>>
  end

  @doc """
  Verify that a binary is signed with a valid signature (by `sign_hmac/2` or `sign_encoded_hmac/2`).

  ## Doctests

      # verifies both `sign_hmac/2` and `sign_encoded_hmac/2`
      iex> "charon!" |> sign_encoded_hmac("secret") |> verify_hmac("secret")
      {:ok, "charon!"}
      iex> "charon!" |> sign_hmac("secret") |> verify_hmac("secret")
      {:ok, "charon!"}

      # returns :invalid_signature error on HMAC mismatch
      iex> "charon!" |> sign_encoded_hmac("secret") |> verify_hmac("wrong")
      {:error, :invalid_signature}
      iex> "charon!" |> sign_hmac("secret") |> verify_hmac("wrong")
      {:error, :invalid_signature}

      # returns :malformed_input when input binary is of unknown format
      iex> verify_hmac("charon!", "secret")
      {:error, :malformed_input}
  """
  @spec verify_hmac(binary, binary) ::
          {:ok, binary} | {:error, :invalid_signature | :malformed_input}
  def verify_hmac(binary, key)

  def verify_hmac(<<"signed.", mac::binary-size(32), ?., data::binary>>, key),
    do: verify(data, key, mac)

  def verify_hmac(<<"signed_u64.", hmac::binary-size(43), ?., data::binary>>, key) do
    case url_decode(hmac) do
      {:ok, hmac} -> verify(data, key, hmac)
      _ -> {:error, :malformed_input}
    end
  end

  def verify_hmac(_, _), do: {:error, :malformed_input}

  @doc """
  Generate a string of cryptographically strong random digits of length `digit_count`.
  """
  @spec strong_random_digits(pos_integer) :: binary
  def strong_random_digits(digit_count) when digit_count >= 0 do
    upper_bound = Integer.pow(10, digit_count)
    generate_digits(0, upper_bound)
  end

  ###########
  # Private #
  ###########

  defp verify(data, key, hmac) do
    if hmac_matches?(data, key, hmac) do
      {:ok, data}
    else
      {:error, :invalid_signature}
    end
  end

  defp generate_digits(acc, upper_bound) when acc < upper_bound do
    <<int1::20, int2::20>> = :crypto.strong_rand_bytes(5)
    acc |> add_valid_digits(int1) |> add_valid_digits(int2) |> generate_digits(upper_bound)
  end

  defp generate_digits(acc, upper_bound) do
    # for digit_count=3; 1000 + rem(10023, 1000) = 1023
    Integer.to_string(upper_bound + rem(acc, upper_bound))
    # 1023 -> "023"
    |> then(fn <<_::binary-size(1), result::binary>> -> result end)
  end

  # 0 <= v <= 1_048_575
  defp add_valid_digits(acc, v) when v < 1_000_000, do: acc * 1_000_000 + v
  defp add_valid_digits(acc, _too_large_unsigned_int), do: acc
end
