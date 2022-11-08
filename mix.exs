defmodule Charon.MixProject do
  use Mix.Project

  def project do
    [
      app: :charon,
      version: "0.0.0+development",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      description: """
      Authentication & sessions for API's.
      """,
      package: [
        licenses: ["Apache-2.0"],
        links: %{github: "https://github.com/weareyipyip/charon"},
        source_url: "https://github.com/weareyipyip/charon"
      ],
      source_url: "https://github.com/weareyipyip/charon",
      name: "Charon",
      docs: [
        source_ref: "master",
        extras: ["./README.md"],
        main: "readme"
      ]
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
      {:jason, "~> 1.0", optional: true},
      {:plug, "~> 1.11"},
      {:mix_test_watch, "~> 1.0", only: [:dev], runtime: false},
      {:redix, "~> 1.1", only: [:test], runtime: false}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
end
