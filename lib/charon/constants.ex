defmodule Charon.Constants do
  @moduledoc false
  defmacro __using__(_opts) do
    quote do
      @private_session_key :charon_session_session
      @private_tokens_key :charon_session_tokens
      @private_access_token_payload_key :charon_session_access_token_payload
      @private_refresh_token_payload_key :charon_session_refresh_token_payload
      @private_auth_error_key :charon_session_auth_error
      @private_token_signature_transport_key :charon_session_token_signature_transport
      @private_user_id_key :charon_session_user_id
      @private_session_id_key :charon_session_session_id
    end
  end
end
