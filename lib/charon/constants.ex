defmodule Charon.Constants do
  @moduledoc false
  defmacro __using__(_opts) do
    quote do
      @session :charon_session
      @tokens :charon_tokens
      @access_token_payload :charon_access_token_payload
      @refresh_token_payload :charon_refresh_token_payload
      @auth_error :charon_auth_error
      @token_signature_transport :charon_token_signature_transport
      @user_id :charon_user_id
      @session_id :charon_session_id
      @bearer_token :charon_bearer_token
      @bearer_token_payload :charon_bearer_token_payload
    end
  end
end
