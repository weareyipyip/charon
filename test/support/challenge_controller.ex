defmodule Charon.ChallengeController do
  use Plug.Router
  alias Charon.{UserContext}
  import Charon.AuthFlowController, only: [json_resp: 3, get_config: 0, get_challenge_map: 0]

  plug(:match)
  plug(:dispatch)

  post "/init_setup/:name" do
    with %{user_id: user_id} <- conn.assigns,
         challenge when not is_nil(challenge) <- Map.get(get_challenge_map(), name),
         {_, user = %{}} <- {:user, UserContext.get_by_id(user_id)},
         {:ok, conn, to_return} <- challenge.setup_init(conn, conn.params, user, get_config()) do
      case to_return do
        nil -> send_resp(conn, 204, "")
        response -> json_resp(conn, 200, response)
      end
    else
      nil -> json_resp(conn, 404, %{error: "challenge not found"})
      {:user, nil} -> json_resp(conn, 404, %{error: "user not found"})
      {:error, msg} -> json_resp(conn, 400, %{error: msg})
    end
  end

  post "/complete_setup/:name" do
    with %{user_id: user_id} <- conn.assigns,
         challenge when not is_nil(challenge) <- Map.get(get_challenge_map(), name),
         {_, user = %{}} <- {:user, UserContext.get_by_id(user_id)},
         {:ok, conn, to_return} <- challenge.setup_complete(conn, conn.params, user, get_config()) do
      case to_return do
        nil -> send_resp(conn, 204, "")
        response -> json_resp(conn, 200, response)
      end
    else
      nil -> json_resp(conn, 404, %{error: "challenge not found"})
      {:user, nil} -> json_resp(conn, 404, %{error: "user not found"})
      {:error, msg} -> json_resp(conn, 400, %{error: msg})
    end
  end
end
