defmodule Charon.Config do
  @moduledoc """
  Config struct.

  All config is read at runtime. So if, for example, you wish to override `:session_ttl`
  based on the username, you can simply alter the config struct in your code.

  That being said, config that HAS to be read at runtime, like secrets,
  is stored as a getter to emphasize the fact and prevent you from accidentally setting
  a compile-time value even if you put the config struct in a module attribute.
  That is why the base secret has to be passed in via `:get_base_secret`.

  ## Keys & defaults

      [
        :token_issuer,
        :get_base_secret,
        access_cookie_name: "_access_token_signature",
        access_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
        # 15 minutes
        access_token_ttl: 15 * 60,
        enforce_browser_cookies: false,
        json_module: Jason,
        optional_modules: %{},
        refresh_cookie_name: "_refresh_token_signature",
        refresh_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
        # 2 months
        refresh_token_ttl: 2 * 30 * 24 * 60 * 60,
        session_store_module: Charon.SessionStore.RedisStore,
        # 1 year
        session_ttl: 365 * 24 * 60 * 60,
        token_factory_module: Charon.TokenFactory.Jwt
      ]

  ## Glossary

   - `:access_cookie_name` Name of the cookie in which the access token or its signature is stored.
   - `:access_cookie_opts` Options passed to `Plug.Conn.put_resp_cookie/3`. Note that `:max_age` is set by `Charon.SessionPlugs` based on the token TTL. Overrides are merged into the defaults.
   - `:access_token_ttl` Time in seconds until a new access token expires. This time may be reduced so that the token does not outlive its session.
   - `:enforce_browser_cookies` If a browser client is detected, enforce that tokens are not returned to it as fully valid bearer tokens, but are transported (wholly or in part) as cookies.
   - `:get_base_secret` Getter for Charon's base secret from which other keys are derived. Make sure it has large entropy (>= 256 bits). For example `fn -> Application.get_env(:my_app, :charon_secret) end`.
   - `:json_module` The JSON module, like `Jason` or `Poison`.
   - `:optional_modules` Configuration for optional modules, like `Charon.TokenFactory.Jwt` or `CharonOauth2`. See the optional module's docs for info on its configuration options.
   - `:refresh_cookie_name` Name of the cookie in which the refresh token or its signature is stored.
   - `:refresh_cookie_opts` Options passed to `Plug.Conn.put_resp_cookie/3`. Note that `:max_age` is set by `Charon.SessionPlugs` based on the token TTL. Overrides are merged into the defaults.
   - `:refresh_token_ttl` Time in seconds until a new refresh token expires. This time may be reduced so that the token does not outlive its session.
   - `:session_store_module` A module that implements `Charon.SessionStore.Behaviour`, used to store sessions.
   - `:session_ttl` Time in seconds until a new session expires OR `:infinite` for non-expiring sessions.
   - `:token_factory_module` A module that implements `Charon.TokenFactory.Behaviour`, used to create and verify authentication tokens.
   - `:token_issuer` Value of the "iss" claim in tokens, for example "https://myapp.com"
  """
  @enforce_keys [:token_issuer, :get_base_secret]
  defstruct [
    :token_issuer,
    :get_base_secret,
    access_cookie_name: "_access_token_signature",
    access_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
    # 15 minutes
    access_token_ttl: 15 * 60,
    enforce_browser_cookies: false,
    json_module:
      if (System.version() |> Version.compare("1.18.0")) in [:eq, :gt] do
        JSON
      else
        Jason
      end,
    optional_modules: %{},
    refresh_cookie_name: "_refresh_token_signature",
    refresh_cookie_opts: [http_only: true, same_site: "Strict", secure: true],
    # 2 months
    refresh_token_ttl: 2 * 30 * 24 * 60 * 60,
    session_store_module: Charon.SessionStore.RedisStore,
    # 1 year
    session_ttl: 365 * 24 * 60 * 60,
    token_factory_module: Charon.TokenFactory.Jwt
  ]

  @type t :: %__MODULE__{
          access_cookie_name: String.t(),
          access_cookie_opts: keyword(),
          access_token_ttl: pos_integer(),
          enforce_browser_cookies: boolean,
          get_base_secret: (-> binary()),
          json_module: module(),
          optional_modules: map(),
          refresh_cookie_name: String.t(),
          refresh_cookie_opts: keyword(),
          refresh_token_ttl: pos_integer(),
          session_store_module: module(),
          session_ttl: pos_integer() | :infinite,
          token_factory_module: module(),
          token_issuer: String.t()
        }

  @doc """
  Build config struct from enumerable (useful for passing in application environment).
  Raises for missing mandatory keys and sets defaults for optional keys.
  Optional modules must implement an `init_config/1` function to process their own config at compile time.

  ## Examples / doctests

      iex> from_enum([])
      ** (ArgumentError) the following keys must also be given when building struct Charon.Config: [:token_issuer, :get_base_secret]

      iex> %Charon.Config{} = from_enum(token_issuer: "https://myapp", get_base_secret: "supersecure")
  """
  @spec from_enum(Enum.t()) :: t()
  def from_enum(enum) do
    __MODULE__ |> struct!(enum) |> process_optional_modules()
  end

  ###########
  # Private #
  ###########

  defp process_optional_modules(config = %{optional_modules: opt_mods}) do
    opt_mods
    |> Map.new(fn {module, config} -> {module, module.init_config(config)} end)
    |> then(fn initialized_opt_mods -> %{config | optional_modules: initialized_opt_mods} end)
  end
end
