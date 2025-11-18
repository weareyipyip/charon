defmodule Charon.Utils.KeyGenerator do
  @moduledoc """
  Derive a key from a base secret using PBKDF2.
  """
  require Logger

  @type opts :: [
          length: pos_integer(),
          iterations: pos_integer(),
          digest: :sha | :sha224 | :sha256 | :sha384 | :sha512,
          log: false | :debug | :info | :warning | :error
        ]

  @doc """
  Derive a new key from `base_secret` using `salt`.

  ## Options

    - `:length` key length in bytes, default 32 (256 bits)
    - `:iterations` hash iterations to derive new key, default 250_000
    - `:digest` hashing algorithm used as pseudo-random function, default `:sha256`
    - `:log` log level for this operation (default `:warning`), or `false` to disable logging. Logging helps identify call sites that may need caching after the v4 breaking change removed the built-in cache.

  ## Doctests

      iex> derive_key("secret", "salt", length: 5, iterations: 1)
      <<56, 223, 66, 139, 48>>
  """
  @spec derive_key(binary(), binary(), opts()) :: binary()
  def derive_key(base_secret, salt, opts \\ []) do
    if l = Keyword.get(opts, :log, :warning), do: Logger.log(l, "deriving key (salt: #{salt})")
    length = opts[:length] || 32
    digest = opts[:digest] || :sha256
    iterations = opts[:iterations] || 250_000
    :crypto.pbkdf2_hmac(digest, base_secret, salt, iterations, length)
  end
end
