if Mix.env() == :test do
  defmodule Charon.DummyRedix do
    def command(_command) do
      {:ok, nil}
    end

    def pipeline(_commands) do
      {:ok, nil}
    end
  end
end
