defmodule Charon.Config do
  @moduledoc """
  Config struct.

      [
        token_factory_module: Charon.Token.SymmetricJwt,
        custom: %{}
      ]
  """
  @enforce_keys [:refresh_token_ttl, :session_ttl, :token_issuer]
  defstruct [
    :refresh_token_ttl,
    :session_ttl,
    :token_issuer,
    access_cookie_name: "_access_token_signature",
    access_cookie_opts: [
      http_only: true,
      same_site: "Strict",
      secure: true
    ],
    access_token_ttl: 1800,
    custom: %{},
    refresh_cookie_name: "_refresh_token_signature",
    refresh_cookie_opts: [
      http_only: true,
      same_site: "Strict",
      secure: true
    ],
    session_store_module: Charon.Sessions.SessionStore.RedisStore,
    token_factory_module: Charon.TokenFactory.SymmetricJwt
  ]

  @type t :: %__MODULE__{
          refresh_token_ttl: pos_integer(),
          session_ttl: pos_integer(),
          token_issuer: String.t(),
          token_factory_module: module(),
          session_store_module: module(),
          custom: map(),
          access_token_ttl: pos_integer(),
          access_cookie_name: String.t(),
          refresh_cookie_name: String.t(),
          access_cookie_opts: keyword(),
          refresh_cookie_opts: keyword()
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.

  ## Examples / doctests

      iex> from_enum([])
      ** (ArgumentError) the following keys must also be given when building struct Charon.Config: [:refresh_token_ttl, :session_ttl, :token_issuer]

      iex> %Charon.Config{} = from_enum([session_ttl: 30 * 24 * 60 * 60, refresh_token_ttl: 24 * 60 * 60, token_issuer: "https://myapp"])
  """
  @spec from_enum(Enum.t()) :: %__MODULE__{}
  def from_enum(enum) do
    struct!(__MODULE__, enum)
  end
end
