defmodule Charon.Internal.Crypto.IvFactory do
  @moduledoc """
  Factory to generate unique but not random IVs for encryption, 128-bits by default.
  The IVs are not suitable for cipher modes that require random IVs, like CBC, OFB and CFB,
  but are suitable for CTR and GCM modes.

  First 42 bits is a millisecond-precision timestamp of the initialization time (allows for ~140 years of operation),
  relative to the UNIX epoch (1970-01-01 00:00:00 UTC) by default.
  Next 10 bits is machine ID (allows for 1024 machines).
  The remaining bits are a per-machine counter.
  A counter overflow will trigger a timestamp increase.
  The theoretical maximum rate is 2^counter-bits IVs per millisecond per machine.

  Warning: the IV's timestamp bits will leak the initialization (machine start) time.
  If that is not acceptable, this factory should not be used.
  On the other hand, the fact that these first bits are a timestamp is an implementation detail,
  that should not be relied upon - it may change in the future.

  The uniqueness guarantees depend on proper machine ID generation and a more or less correct clock on the machines.
  Specifically, the UTC clock has to have progressed between initializations (machine restarts).

  This module uses `:atomics` to generate unique IVs in a concurrent environment,
  and `:persistent_term` to store write-once read-often initialization state,
  resulting in a very fast and efficient IV generation.

  Inspired by Twitter snowflake IDs.
  """
  alias Charon.Internal.Crypto.MachineId

  @ts_bits 42
  @id_bits 10
  @min_size 64

  @doc """
  Initializes the IV factory with the given options.

  ## Options

    * `:name` - The name of the IV factory (default: module name).
    * `:iv_size` - The size of the IV in bits (default: 128). Must be at least 64 bits.
    * `:epoch` - The epoch time in milliseconds to use as the base for the timestamp (default: 0 / UNIX).

  ## Examples

      iex> IvFactory.init(name: :small, iv_size: 64)
      :ok

      iex> IvFactory.init(name: :medium, iv_size: 72)
      :ok

      iex> IvFactory.init(name: :large, iv_size: 80)
      :ok

      iex> IvFactory.init(name: :custom, iv_size: 128, epoch: 1609459200000)
      :ok
  """
  @spec init(keyword) :: :ok
  def init(opts \\ []) do
    name = opts[:name] || __MODULE__
    iv_size = opts[:iv_size] || 128
    epoch = opts[:epoch] || 0
    if iv_size < @min_size, do: raise("iv size < #{@min_size} bits is not supported")
    if rem(iv_size, 8) != 0, do: raise("iv size must be a multiple of 8")

    machine_id = MachineId.machine_id()
    if machine_id < 0 or machine_id > 1023, do: raise("machine ID out of range 0-1023")

    iv_count_bits = iv_size - @ts_bits - @id_bits
    # atomics can only handle 64-bit unsigned integers
    cycle_bits = min(64, iv_count_bits)
    cycle_size = Integer.pow(2, cycle_bits)

    init_at = System.system_time(:millisecond) - epoch

    if init_at > Integer.pow(2, @ts_bits) - 365 * 24 * 60 * 60 * 1000,
      do: raise("timestamp overflow imminent")

    mono_delta = init_at - System.monotonic_time(:millisecond)

    counter_ref = :atomics.new(1, signed: false)
    # the counter will overflow to 0 on the first IV generation
    :atomics.put(counter_ref, 1, Integer.pow(2, 64) - 1)

    state = {machine_id, iv_count_bits, cycle_size, init_at, mono_delta, counter_ref, epoch}
    :ok = :persistent_term.put(name, state)
  end

  @doc """
  Generates a new initialization vector (IV) for cryptographic operations.

  This function creates a secure random IV that can be used for encryption algorithms requiring an IV.

  ## Examples

      iex> generate_iv()
      <<207, 14, 112, 45, 89, 163, 210, 78, 154, 233, 112, 56, 246, 199, 188, 122>>

  """
  @spec generate_iv(term) :: binary
  def generate_iv(name \\ __MODULE__) do
    {machine_id, iv_count_bits, cycle_size, init_at, mono_delta, counter_ref, _} =
      :persistent_term.get(name)

    # we can generate 10B IV/s for 60 years straight before the unsigned 64-bits int overflows
    # so we don't need to worry about the atomic counter itself overflowing
    count = :atomics.add_get(counter_ref, 1, 1)

    # but we do need to worry about the IV's counter - which may be only 12 bits for a 64-bit IV - overflowing
    cycle = div(count, cycle_size)
    count = rem(count, cycle_size)

    # the iv timestamp is actually an init timestamp + cycle counter
    timestamp = init_at + cycle

    # with small counters in the iv, we may need to wait for the monotonic clock to catch up to the iv timestamp
    # with 96-bits ivs, the counter is 44 bits, meaning we can generate 2^44 IVs per ms (a.k.a. 1.5 PB/ms)
    # before the counter overflows
    if iv_count_bits < 44, do: wait_until(timestamp, mono_delta)

    <<timestamp::unsigned-@ts_bits, machine_id::unsigned-@id_bits,
      count::unsigned-size(iv_count_bits)>>
  end

  @doc """
  Returns information about an IV.

  This is a convenience function for debugging.
  An IV should not be used for anything other than encryption,
  and the fact that it contains a timestamp, machine ID and counter is an implementation detail.
  """
  @spec iv_info(binary, atom | module) :: %{
          count: integer(),
          datetime: DateTime.t(),
          machine_id: integer(),
          timestamp: non_neg_integer(),
          cycle: integer(),
          total_count: integer()
        }
  def iv_info(iv, name \\ __MODULE__) do
    {_, _, cycle_size, init_at, _, _, epoch} = :persistent_term.get(name)
    count_size = bit_size(iv) - @ts_bits - @id_bits

    <<timestamp::unsigned-@ts_bits, machine_id::unsigned-@id_bits,
      count::unsigned-size(count_size)>> = iv

    cycle = timestamp - init_at
    total_count = cycle * cycle_size + count
    timestamp = timestamp + epoch
    datetime = DateTime.from_unix!(timestamp, :millisecond)

    %{
      timestamp: timestamp,
      machine_id: machine_id,
      count: count,
      datetime: datetime,
      cycle: cycle,
      total_count: total_count
    }
  end

  ###########
  # Private #
  ###########

  defp wait_until(timestamp, mono_delta) do
    now = time_from_mono_delta(mono_delta)

    if timestamp > now do
      :timer.sleep(timestamp - now)
    end
  end

  defp time_from_mono_delta(mono_delta), do: System.monotonic_time(:millisecond) + mono_delta
end
