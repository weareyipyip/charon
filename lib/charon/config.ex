defmodule Charon.Config do
  @moduledoc """
  Config struct. Keys & defaults:

      [
        :password_hashing_module,
        :token_issuer,
        :update_user_callback,
        access_cookie_name: "_access_token_signature",
        access_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
        # 15 minutes
        access_token_ttl: 15 * 60,
        auth_challenge_setup_token_param: "setup_challenge_token",
        # 10 minutes
        auth_flow_ttl: 10 * 60,
        current_password_param: "password",
        custom: %{},
        enabled_auth_challenges_field: :enabled_challenges,
        password_hash_field: :password_hash,
        refresh_cookie_name: "_refresh_token_signature",
        refresh_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
        # 2 months
        refresh_token_ttl: 2 * 30 * 24 * 60 * 60,
        session_store_module: Charon.SessionStore.RedisStore,
        # 1 year
        session_ttl: 365 * 24 * 60 * 60,
        token_factory_module: Charon.TokenFactory.SymmetricJwt
      ]

  Note that all config is compile-time config.
  Runtime configuration properties should be provided in the form of getters,
  like the custom config of `Charon.TokenFactory.SymmetricJwt`.
  """
  @enforce_keys [:token_issuer, :update_user_callback, :password_hashing_module]
  defstruct [
    :password_hashing_module,
    :token_issuer,
    :update_user_callback,
    access_cookie_name: "_access_token_signature",
    access_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
    # 15 minutes
    access_token_ttl: 15 * 60,
    auth_challenge_setup_token_param: "setup_challenge_token",
    # 10 minutes
    auth_flow_ttl: 10 * 60,
    current_password_param: "password",
    custom: %{},
    enabled_auth_challenges_field: :enabled_challenges,
    password_hash_field: :password_hash,
    refresh_cookie_name: "_refresh_token_signature",
    refresh_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
    # 2 months
    refresh_token_ttl: 2 * 30 * 24 * 60 * 60,
    session_store_module: Charon.SessionStore.RedisStore,
    # 1 year
    session_ttl: 365 * 24 * 60 * 60,
    token_factory_module: Charon.TokenFactory.SymmetricJwt
  ]

  @type t :: %__MODULE__{
          access_cookie_name: String.t(),
          access_cookie_opts: keyword(),
          access_token_ttl: pos_integer(),
          auth_challenge_setup_token_param: atom() | String.t(),
          auth_flow_ttl: pos_integer(),
          current_password_param: atom() | String.t(),
          custom: map(),
          enabled_auth_challenges_field: atom(),
          password_hash_field: atom(),
          password_hashing_module: module(),
          refresh_cookie_name: String.t(),
          refresh_cookie_opts: keyword(),
          refresh_token_ttl: pos_integer(),
          session_store_module: module(),
          session_ttl: pos_integer(),
          token_factory_module: module(),
          token_issuer: String.t(),
          update_user_callback:
            (integer() | binary() | map(), map() -> {:ok, map()} | {:error, map() | binary()})
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.

  ## Examples / doctests

      iex> from_enum([])
      ** (ArgumentError) the following keys must also be given when building struct Charon.Config: [:token_issuer, :update_user_callback, :password_hashing_module]

      iex> %Charon.Config{} = from_enum(token_issuer: "https://myapp", update_user_callback: fn _, _ -> nil end, password_hashing_module: __MODULE__)
  """
  @spec from_enum(Enum.t()) :: %__MODULE__{}
  def from_enum(enum) do
    struct!(__MODULE__, enum)
  end
end
