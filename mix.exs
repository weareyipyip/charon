defmodule Charon.MixProject do
  use Mix.Project

  def project do
    [
      app: :charon,
      version: "0.0.0+development",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.21", only: [:dev, :test], runtime: false},
      {:jason, "~> 1.0"},
      {:plug, "~> 1.0"},
      {:mix_test_watch, "~> 1.0", only: [:dev], runtime: false},
      {:mock, "~> 0.3", only: [:test], runtime: false}
    ]
  end
end
