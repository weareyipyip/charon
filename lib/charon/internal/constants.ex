defmodule Charon.Internal.Constants do
  @moduledoc false
  defmacro __using__(_opts) do
    quote do
      @access_token_payload :charon_access_token_payload
      @auth_error :charon_auth_error
      @bearer_token :charon_bearer_token
      @bearer_token_payload :charon_bearer_token_payload
      @refresh_token_payload :charon_refresh_token_payload
      @session :charon_session
      @session_id :charon_session_id
      @token_signature_transport :charon_token_signature_transport
      @tokens :charon_tokens
      @user_id :charon_user_id
      @resp_cookies :charon_resp_cookies
    end
  end
end
