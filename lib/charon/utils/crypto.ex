defmodule Charon.Utils.Crypto do
  @moduledoc """
  Encrypt/decrypt, sign/verify, secure compare binaries etc.
  """
  import Charon.Internal

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
  Constant time memory comparison for fixed length binaries, such as results of HMAC computations.

  Returns true if the binaries are identical, false if they are of the same length but not identical. The function raises an error:badarg exception if the binaries are of different size.
  """
  @spec constant_time_compare(binary, binary) :: boolean()
  if function_exported?(:crypto, :hash_equals, 2) do
    def constant_time_compare(bin_a, bin_b), do: :crypto.hash_equals(bin_a, bin_b)
  else
    def constant_time_compare(bin_a, bin_b), do: Plug.Crypto.secure_compare(bin_a, bin_b)
  end

  @doc """
  Generate a random URL-encoded string of `byte_size` bytes.
  """
  @spec random_url_encoded(pos_integer()) :: binary
  def random_url_encoded(byte_size) do
    byte_size |> :crypto.strong_rand_bytes() |> url_encode()
  end

  @doc """
  Calculate a HMAC of data using key. The algorithm is #{@hmac_alg}.
  """
  @spec hmac(iodata, binary) :: binary
  def hmac(data, key), do: :crypto.mac(:hmac, @hmac_alg, key, data)
end
