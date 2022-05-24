defmodule Charon.Sessions.SessionStore.RedisStoreTest do
  use ExUnit.Case, async: false
  alias Charon.Sessions.SessionStore.RedisStore
  alias Charon.DummyRedix
  import Mock

  @prefix "sess_"
  @config %{custom: %{charon_redis_store: %{redix_module: DummyRedix, key_prefix: @prefix}}}
  @sid "a"
  @uid 1
  @session %{id: @sid, user_id: @uid}
  @serialized :erlang.term_to_binary(@session)

  describe "get/3" do
    test "uses both user_id and session_id in key" do
      with_mock DummyRedix, command: fn _ -> {:ok, nil} end do
        RedisStore.get(@sid, @uid, @config)
        assert_called(DummyRedix.command(["GET", [@prefix, ".s.", @uid, ?., @sid]]))
      end
    end

    test "returns nil if not found (or expired)" do
      with_mock DummyRedix, command: fn _ -> {:ok, nil} end do
        assert nil == RedisStore.get(@sid, @uid, @config)
      end
    end

    test "returns deserialized session" do
      with_mock DummyRedix, command: fn _ -> {:ok, @serialized} end do
        assert @session == RedisStore.get(@sid, @uid, @config)
      end
    end

    test "returns error" do
      with_mock DummyRedix, command: fn _ -> {:error, :boom} end do
        assert {:error, :boom} = RedisStore.get(@sid, @uid, @config)
      end
    end
  end

  describe "upsert/3" do
    test "uses both user_id and session_id in key and sets ttl" do
      ttl = 100

      with_mock DummyRedix, pipeline: fn _ -> {:ok, nil} end do
        assert :ok = RedisStore.upsert(@session, ttl, @config)

        assert_called(
          DummyRedix.pipeline([
            ["MULTI"],
            ["ZADD", ["sess_", ".u.", @uid], :_, ["sess_", ".s.", @uid, ?., @sid]],
            ["SET", ["sess_", ".s.", @uid, ?., @sid], @serialized, "EX", ttl],
            ["EXEC"]
          ])
        )
      end
    end

    test "returns error" do
      with_mock DummyRedix, pipeline: fn _ -> {:error, :boom} end do
        assert {:error, :boom} = RedisStore.upsert(@session, 100, @config)
      end
    end
  end

  describe "delete/2" do
    test "returns ok when not found" do
      with_mock DummyRedix, command: fn _ -> {:ok, nil} end do
        assert :ok = RedisStore.delete(@sid, @uid, @config)
        assert_called(DummyRedix.command(["DEL", [@prefix, ".s.", @uid, ?., @sid]]))
      end
    end

    test "returns ok when found" do
      with_mock DummyRedix, command: fn _ -> {:ok, @uid} end do
        assert :ok = RedisStore.delete(@sid, @uid, @config)
      end
    end

    test "returns error" do
      with_mock DummyRedix, command: fn _ -> {:error, :boom} end do
        assert {:error, :boom} = RedisStore.delete(@sid, @uid, @config)
      end
    end
  end

  describe "get_all/2" do
    test "grabs the user's sessions from their set" do
      with_mock DummyRedix,
        command: fn
          ["ZRANGE", [@prefix, ".u.", @uid], _, "+inf", "BYSCORE"] -> {:ok, [@sid]}
          ["MGET", @sid] -> {:ok, [@serialized]}
        end do
        assert [@session] = RedisStore.get_all(@uid, @config)
        assert_called_exactly(DummyRedix.command(:_), 2)
      end
    end
  end

  describe "delete_all/2" do
    test "removes all sessions and the user's session set" do
      with_mock DummyRedix,
        command: fn
          ["ZRANGE", [@prefix, ".u.", @uid], 0, -1] -> {:ok, [@sid]}
          ["DEL", [@prefix, ".u.", @uid], "a"] -> {:ok, [@serialized]}
        end do
        assert :ok = RedisStore.delete_all(@uid, @config)
        assert_called_exactly(DummyRedix.command(:_), 2)
      end
    end
  end
end
