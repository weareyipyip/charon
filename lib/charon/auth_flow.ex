defmodule Charon.AuthFlow do
  @moduledoc """
  An authentication flow that can be used to log in.
  A flow consists of stages, each of which has to be passed in order to log in.
  A stage consists of challenges, one of which has to be passed in order to pass the stage.
  """
  use Charon.Constants
  alias __MODULE__.Stage
  alias Charon.{Internal, Config}
  alias Charon.Models.Session
  alias Charon.AuthChallenge

  @token_type "protosession"

  @enforce_keys [:stages, :name]
  defstruct [:stages, :name]

  @typedoc """
  An authentication flow that can be used to log in.
  A flow consists of stages, each of which has to be passed in order to log in.
  A stage consists of challenges, one of which has to be passed in order to pass the stage.
  """
  @type t :: %__MODULE__{stages: [Stage.t()], name: String.t()}

  @typedoc """
  A set of auth flows.
  """
  @type flow_set :: %{required(String.t()) => t()}

  @doc """
  Initialize a new auth flow. Creates a protosession and a token to complete its auth flow with.
  """
  @spec init(map() | struct(), flow_set(), String.t(), String.t(), Config.t()) ::
          {:ok, String.t(), Stage.t()} | {:error, String.t()}
  def init(user, flow_set, flow_name, sig_transport, config) do
    with _flow = %{} <- get_flow(flow_set, flow_name) do
      sig_transport = Internal.parse_sig_transport(sig_transport)

      session =
        Session.new(config,
          type: :proto,
          user_id: user.id,
          extra_payload: %{stage: 0, flow: flow_name, sig_transport: sig_transport}
        )

      :ok = config.session_store_module.upsert(session, config.auth_flow_ttl, config)
      {:ok, token} = create_protosession_token(session, config)
      {:ok, stage} = get_stage(flow_set, session, :current)
      {:ok, token, stage}
    else
      _ -> {:error, "flow not recognized"}
    end
  end

  @doc """
  Verify a protosession token, load its protosession and find the requested challenge.
  """
  @spec process_token(String.t(), flow_set(), String.t(), Charon.Config.t()) ::
          {:ok, Charon.AuthChallenge.t(), Charon.Models.Session.t()} | {:error, String.t()}
  def process_token(token, flows, name, config) do
    with {:ok, session} <- verify_token(token, config),
         {:ok, stage} <- get_stage(flows, session),
         challenge when not is_nil(challenge) <- Stage.get_challenge(stage, name) do
      {:ok, challenge, session}
    else
      nil -> {:error, "challenge not recognized"}
      error -> error
    end
  end

  @doc """
  After completing a challenge, pass the result to this function.
  If the challenge is completed successfully and it is the final stage
  of an auth flow, a session is created and tokens are handed out.
  If the challenge is completed successfully but it is not the final stage
  of an auth flow, the next stage is returned.
  If the challenge fails, the error is returned.
  """
  @spec handle_challenge_result(
          {:ok, Plug.Conn.t(), map() | nil} | {:error, String.t() | map()},
          flow_set(),
          Session.t(),
          Plug.Conn.t(),
          Config.t(),
          keyword()
        ) ::
          {:flow_complete, Plug.Conn.t(), map()}
          | {:challenge_complete, Plug.Conn.t(), %{next_stage: Stage.t()}}
          | {:error, String.t() | map()}
  def handle_challenge_result(result, flow_set, session, conn, config, opts \\ [])

  def handle_challenge_result({:ok, conn, to_return}, flow_set, session, conn, config, opts) do
    to_return = to_return || %{}

    case get_stage(flow_set, session, :next) do
      {:ok, next_stage} ->
        {:ok, _session} = bump_protosession_stage(session, config)
        {:challenge_complete, conn, Map.put(to_return, :next_stage, next_stage)}

      {:error, "stage not found"} ->
        # hand out tokens! hurray!
        conn
        |> Internal.put_private(%{
          @token_signature_transport => session.extra_payload.sig_transport,
          @session => %{session | extra_payload: %{}}
        })
        |> Charon.SessionPlugs.upsert_session(
          config,
          Keyword.get(opts, :upsert_session_opts, [])
        )
        |> then(fn conn ->
          %{@session => session, @tokens => tokens} = conn.private
          to_return = Map.merge(to_return, %{session: session, tokens: tokens})
          {:flow_complete, conn, to_return}
        end)
    end
  end

  def handle_challenge_result(error, _, _, _, _, _), do: error

  @doc """
  Create a flow set from a list of `t:Charon.AuthFlow.t()`.
  """
  @spec list_to_flow_set([__MODULE__.t()]) :: flow_set()
  def list_to_flow_set(flow_list) do
    Map.new(flow_list, fn flow ->
      Enum.all?(flow.stages, &match?(%Stage{}, &1)) || raise "stages must be valid structs"
      {flow.name, flow}
    end)
  end

  @doc """
  Create a challenge map (challenges mapped to their names) from a flow set.
  """
  @spec to_challenge_map(flow_set()) :: %{required(String.t()) => AuthChallenge.t()}
  def to_challenge_map(flow_set) do
    Enum.reduce(flow_set, %{}, fn {_name, flow}, acc ->
      Enum.reduce(flow.stages, acc, fn stage, acc ->
        Map.merge(acc, stage.challenges)
      end)
    end)
  end

  ###########
  # Private #
  ###########

  defp get_stage(flow_set, session, stage \\ :current) do
    index_modifier =
      case stage do
        :current -> 0
        :next -> 1
      end

    flow_set
    |> get_flow(session)
    |> Map.get(:stages)
    |> Enum.at(session.extra_payload.stage + index_modifier)
    |> case do
      nil -> {:error, "stage not found"}
      stage = %Stage{} -> {:ok, stage}
    end
  end

  defp get_flow(flow_set, _session = %{extra_payload: %{flow: name}}), do: Map.get(flow_set, name)
  defp get_flow(flow_set, name), do: Map.get(flow_set, name)

  defp create_protosession_token(session, config) do
    now = Internal.now()

    %{
      exp: now + config.auth_flow_ttl,
      nbf: now,
      sid: session.id,
      sub: session.user_id,
      type: @token_type
    }
    |> config.token_factory_module.sign(config)
  end

  defp bump_protosession_stage(session, config) do
    extra = session.extra_payload
    session = %{session | extra_payload: %{extra | stage: extra.stage + 1}}
    :ok = config.session_store_module.upsert(session, config.auth_flow_ttl, config)
    {:ok, session}
  end

  # @doc """
  # Verify a protosession token and loads its protosession.
  # """
  # @spec verify_token(String.t(), Config.t()) :: {:ok, Session.t()} | {:error, String.t()}
  defp verify_token(token, config) do
    with {:ok, payload} <- config.token_factory_module.verify(token, config),
         now = Internal.now(),
         {_,
          %{
            "exp" => exp,
            "nbf" => nbf,
            "sid" => session_id,
            "sub" => user_id,
            "type" => type
          }} <- {:token_pl, payload},
         {_, true} <- {:valid, nbf <= now and exp > now},
         {_, true} <- {:type, type == @token_type},
         {_, session = %{}} <-
           {:session, config.session_store_module.get(session_id, user_id, config)},
         {_, true} <- {:session_type, session.type == :proto} do
      {:ok, session}
    else
      error = {:error, _} -> error
      {:token_pl, _} -> {:error, "unexpected token payload"}
      {:valid, _} -> {:error, "token expired or not yet valid"}
      {:type, _} -> {:error, "unexpected token type"}
      {:session, _} -> {:error, "protosession not found"}
      {:session_type, _} -> {:error, "session already signed in"}
    end
  end
end
