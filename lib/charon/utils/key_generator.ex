defmodule Charon.Utils.KeyGenerator do
  @moduledoc """
  Derive a key from a base secret using PBKDF2.
  """

  @type opts :: [
          length: pos_integer(),
          iterations: pos_integer(),
          digest: :sha | :sha224 | :sha256 | :sha384 | :sha512
        ]

  @doc """
  Derive a new key from `base_secret` using `salt`.
  The result is cached using `FastGlobal` with key `#{__MODULE__}`.

  ## Options

    - `:length` key length in bytes, default 32 (256 bits)
    - `:iterations` hash iterations to derive new key, default 250_000
    - `:digest` hashing algorithm used as pseudo-random function, default `:sha256`


  ## Doctests

      iex> derive_key("secret", "salt", length: 5, iterations: 1)
      <<56, 223, 66, 139, 48>>

      # key is returned from cache based on function args
      iex> FastGlobal.put(KeyGenerator, %{{"secret", "salt", [length: 5, iterations: 1]} => "supersecret"})
      iex> derive_key("secret", "salt", length: 5, iterations: 1)
      "supersecret"
  """
  @spec derive_key(binary, binary, opts) :: binary()
  def derive_key(base_secret, salt, opts \\ []) do
    cache = FastGlobal.get(__MODULE__) || %{}

    if cached = Map.get(cache, {base_secret, salt, opts}) do
      cached
    else
      length = opts[:length] || 32
      digest = opts[:digest] || :sha256
      iterations = opts[:iterations] || 250_000

      :crypto.pbkdf2_hmac(digest, base_secret, salt, iterations, length)
      |> tap(&FastGlobal.put(__MODULE__, Map.put(cache, {base_secret, salt, opts}, &1)))
    end
  end
end
