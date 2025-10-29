if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.SessionStore.RedisStore.LuaFunctions do
    @moduledoc false
    require Logger

    @hashed_version Mix.Project.config()
                    |> Keyword.fetch!(:version)
                    |> :erlang.phash2(Integer.pow(2, 32))
                    |> to_string()
    @upsert_function_name "opt_lock_upsert_#{@hashed_version}"

    @doc """
    Returns the Redis command to call Redis function "charon_opt_lock_upsert",
    which upserts a session while optimistically locking on `lock_version`.
    On a locking failure, `"CONFLICT"` is returned and no state is changed.

    On a locking success:
     - the serialized `session` is stored under its `sid` in `session_set_key`
     - `lock_version` is stored under `l.sid` in `session_set_key`
    """
    @spec opt_lock_upsert_cmd(iodata, iodata, iodata, integer, iodata, integer) ::
            [integer] | binary()
    def opt_lock_upsert_cmd(session_set_key, sid, lock_key, lock_version, session, expires_at) do
      [
        "FCALL",
        @upsert_function_name,
        _key_count = 1,
        session_set_key,
        sid,
        lock_key,
        lock_version,
        session,
        expires_at
      ]
    end

    def register_functions_cmd() do
      with <<priv_dir::binary>> <- :code.priv_dir(:charon) |> to_string(),
           {:ok, script} <- File.read(priv_dir <> "/redis_functions.lua") do
        script = String.replace(script, "0.0.0+development", @hashed_version)
        load_function_command = ["FUNCTION", "LOAD", "REPLACE", script]
        %{expected_result: "charon_redis_store_#{@hashed_version}", cmd: load_function_command}
      else
        error -> raise "Could not read Redis functions: #{inspect(error)}"
      end
    end
  end
end
