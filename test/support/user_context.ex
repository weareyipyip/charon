defmodule Charon.UserContext do
  alias Charon.TestRedix

  @recovery_code :crypto.strong_rand_bytes(16)
  @default_user %{
    id: 1,
    email: "a@b.c",
    enabled_challenges: ~w(password totp recovery_code pre_sent bypass_stage),
    password: "supersecret",
    password_hash: Bcrypt.hash_pwd_salt("supersecret"),
    totp_seed: :crypto.strong_rand_bytes(32),
    recovery_code: Base.encode32(@recovery_code, padding: false, case: :lower),
    recovery_code_hashes: [
      :crypto.hash(:blake2b, @recovery_code) |> Base.url_encode64(padding: false)
    ]
  }
  def new(overrides \\ []), do: Map.merge(@default_user, Map.new(overrides))

  def get_by_id(id), do: TestRedix.command(["GET", id]) |> deserialize()
  def get_by_email(email), do: TestRedix.command(["GET", email]) |> deserialize()

  def update(user = %{}, params) do
    user |> Map.merge(to_atom_keys(params)) |> insert()
  end

  def update(id, params) do
    case get_by_id(id) do
      user = %{} -> update(user, params)
      nil -> nil
    end
  end

  def insert(user = %{email: email, id: id}) do
    serialized = serialize(user)
    {:ok, _} = TestRedix.pipeline([["SET", id, serialized], ["SET", email, serialized]])
    {:ok, user}
  end

  defp serialize(term), do: :erlang.term_to_binary(term)
  defp deserialize({:ok, nil}), do: nil
  defp deserialize({:ok, binary}), do: :erlang.binary_to_term(binary)

  defp to_atom_keys(map) do
    Map.new(map, fn
      {<<k::binary>>, v} -> {String.to_atom(k), v}
      {k, v} -> {k, v}
    end)
  end
end
