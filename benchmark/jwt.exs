alias Charon.TokenFactory.Jwt

defmodule CharonBench do
  alias Charon.Utils.KeyGenerator
  alias Charon.Utils.PersistentTermCache

  def secret(), do: "supersecret"

  @config Charon.Config.from_enum(
            token_issuer: "my_test_app",
            get_base_secret: &__MODULE__.secret/0,
            optional_modules: %{Jwt => [get_keyset: &__MODULE__.keyset/1]}
          )

  def config(jwt_overrides),
    do: Charon.TestHelpers.override_opt_mod_conf(@config, Jwt, jwt_overrides)

  def keyset(_) do
    PersistentTermCache.get_or_create(:jwt_keyset, fn ->
      base_secret = secret()

      for {id, alg} <- [a: :hmac_sha256, b: :hmac_sha512, c: :poly1305], into: %{} do
        {to_string(id), {alg, KeyGenerator.derive_key(base_secret, to_string(id), log: false)}}
      end
      |> Map.put("d", Jwt.gen_keypair(:eddsa_ed25519))
    end)
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

{:ok, sha256_jwt} = Jwt.sign(payload, sha256_conf)
{:ok, sha512_jwt} = Jwt.sign(payload, sha512_conf)
{:ok, poly1305_jwt} = Jwt.sign(payload, poly1305_conf)
{:ok, ed25519_jwt} = Jwt.sign(payload, ed25519_conf)

%{
  "sign hmac-sha256" => [fn -> Jwt.sign(payload, sha256_conf) end, tasks: tasks],
  "sign hmac-sha512" => [fn -> Jwt.sign(payload, sha512_conf) end, tasks: tasks],
  "sign poly1305" => [fn -> Jwt.sign(payload, poly1305_conf) end, tasks: tasks],
  "sign ed25519" => [fn -> Jwt.sign(payload, ed25519_conf) end, tasks: tasks],
  "sign poly1305 nonrand" => [fn -> Jwt.sign(payload, poly1305_nonrand_conf) end, tasks: tasks],
  "verify hmac-sha256" => [fn -> Jwt.verify(sha256_jwt, sha256_conf) end, tasks: tasks],
  "verify hmac-sha512" => [fn -> Jwt.verify(sha512_jwt, sha512_conf) end, tasks: tasks],
  "verify poly1305" => [fn -> Jwt.verify(poly1305_jwt, poly1305_conf) end, tasks: tasks],
  "verify ed25519" => [fn -> Jwt.verify(ed25519_jwt, ed25519_conf) end, tasks: tasks],
  "verify poly1305 nonrand" => [
    fn -> Jwt.verify(poly1305_jwt, poly1305_nonrand_conf) end,
    tasks: tasks
  ]
}
|> Benchmark.bench_many()
|> Benchmark.format_results()
|> IO.puts()
