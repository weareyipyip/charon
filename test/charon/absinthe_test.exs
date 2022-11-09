defmodule Charon.AbsintheTest do
  use ExUnit.Case, async: true
  use Charon.Constants
  alias Plug.Conn
  alias Absinthe.Blueprint
  alias Charon.Absinthe, as: CharonAbsinthe

  describe "send_context_cookies/2" do
    test "passes through conn if no cookies set in context" do
      conn = %Conn{resp_cookies: %{stale: "cookies!"}}
      blueprint = %Blueprint{}
      assert ^conn = CharonAbsinthe.send_context_cookies(conn, blueprint)
    end

    test "merges context's response cookies into the conn" do
      cookies = %{fresh: "cookies!"}
      conn = %Conn{resp_cookies: %{stale: "cookies!"}}
      blueprint = %Blueprint{execution: %{context: %{@resp_cookies => cookies}}}
      conn = CharonAbsinthe.send_context_cookies(conn, blueprint)
      assert %{fresh: "cookies!", stale: "cookies!"} = conn.resp_cookies
    end
  end
end
