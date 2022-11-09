defmodule Charon.Absinthe.PostSessionChangeMiddlewareTest do
  use ExUnit.Case, async: true
  use Charon.Constants
  alias Absinthe.Resolution
  alias Charon.Absinthe.PostSessionChangeMiddleware

  describe "call/2" do
    test "passes through resolution without resp_cookies" do
      res = %Resolution{}
      assert ^res = PostSessionChangeMiddleware.call(res, nil)
    end

    test "puts resolution.value.resp_cookies in the context under key #{@resp_cookies}" do
      cookies = %{yum: "cookies!"}
      res = %Resolution{context: %{}, value: %{resp_cookies: cookies}}
      assert %{context: %{@resp_cookies => ^cookies}} = PostSessionChangeMiddleware.call(res, nil)
    end
  end
end
