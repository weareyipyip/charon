alias TestApp.Charon.CompiledJwt
alias Charon.TokenFactory.Jwt

defmodule CharonBench do
  alias Charon.Utils.PersistentTermCache

  @ed25519_key {<<89, 196, 121, 98, 207, 119, 202, 129, 121, 201, 104, 251, 68, 82, 231, 25, 12,
                  59, 242, 72, 17, 98, 224, 172, 56, 38, 249, 1, 233, 220, 67, 67>>,
                <<33, 171, 1, 67, 222, 166, 136, 27, 213, 202, 162, 120, 214, 106, 95, 4, 87, 53,
                  185, 91, 30, 85, 159, 43, 181, 90, 124, 10, 58, 217, 98, 115>>}
  @poly1305_key <<61, 95, 141, 243, 240, 127, 73, 153, 220, 173, 198, 206, 235, 176, 136, 241,
                  135, 160, 59, 154, 250, 52, 156, 36, 49, 44, 83, 199, 61, 103, 36, 24>>

  def secret(), do: "supersecret"

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &__MODULE__.secret/0,
            optional_modules: %{Jwt => [get_keyset: &__MODULE__.keyset/1]}
          )

  def config(jwt_overrides),
    do: Charon.TestHelpers.override_opt_mod_conf(@config, Jwt, jwt_overrides)

  def keyset(_) do
    %{
      "a" => {:hmac_sha256, "supersecret"},
      "b" => {:hmac_sha512, "supersecret"},
      "c" => {:poly1305, @poly1305_key},
      "d" => {:eddsa_ed25519, @ed25519_key}
    }
  end

  def counter_nonce() do
    ref =
      PersistentTermCache.get_or_create(:atomics_ref, fn ->
        :atomics.new(1, signed: false)
      end)

    <<:atomics.add_get(ref, 1, 1)::96>>
  end
end

# warm caches
CharonBench.keyset(nil)
CharonBench.counter_nonce()

tasks = 1

payload = %{
  some: "payload",
  lets: "do this",
  numbers: 102_301_923,
  hello: "world",
  say:
    "hi for me. I just want the payload to have some bulk because that way it is more realistic."
}

sha256_conf = CharonBench.config(signing_key: "a")
sha512_conf = CharonBench.config(signing_key: "b")
poly1305_conf = CharonBench.config(signing_key: "c")

poly1305_nonrand_conf =
  CharonBench.config(signing_key: "c", gen_poly1305_nonce: &CharonBench.counter_nonce/0)

ed25519_conf = CharonBench.config(signing_key: "d")

{:ok, sha256_jwt} = CompiledJwt.Sha256.sign(payload, sha256_conf)
{:ok, sha512_jwt} = Jwt.sign(payload, sha512_conf)
{:ok, poly1305_jwt} = CompiledJwt.Poly1305.sign(payload, poly1305_conf)
{:ok, ed25519_jwt} = CompiledJwt.Ed25519.sign(payload, ed25519_conf)

%{
  "sign hmac-sha256" => [fn -> Jwt.sign(payload, sha256_conf) end, tasks: tasks],
  "sign compiled hmac-sha256" => [
    fn -> CompiledJwt.Sha256.sign(payload, sha256_conf) end,
    tasks: tasks
  ],
  "sign hmac-sha512" => [fn -> Jwt.sign(payload, sha512_conf) end, tasks: tasks],
  "sign poly1305" => [fn -> Jwt.sign(payload, poly1305_conf) end, tasks: tasks],
  "sign ed25519" => [fn -> Jwt.sign(payload, ed25519_conf) end, tasks: tasks],
  "sign poly1305 nonrand" => [fn -> Jwt.sign(payload, poly1305_nonrand_conf) end, tasks: tasks],
  "sign compiled poly1305 nonrand" => [
    fn -> CompiledJwt.Poly1305.sign(payload, poly1305_nonrand_conf) end,
    tasks: tasks
  ],
  "verify hmac-sha256" => [fn -> Jwt.verify(sha256_jwt, sha256_conf) end, tasks: tasks],
  "verify compiled hmac-sha256" => [
    fn -> CompiledJwt.Sha256.verify(sha256_jwt, sha256_conf) end,
    tasks: tasks
  ],
  "verify hmac-sha512" => [fn -> Jwt.verify(sha512_jwt, sha512_conf) end, tasks: tasks],
  "verify poly1305" => [fn -> Jwt.verify(poly1305_jwt, poly1305_conf) end, tasks: tasks],
  "verify ed25519" => [fn -> Jwt.verify(ed25519_jwt, ed25519_conf) end, tasks: tasks],
  "verify compiled poly1305" => [
    fn -> CompiledJwt.Poly1305.verify(poly1305_jwt, poly1305_conf) end,
    tasks: tasks
  ]
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
