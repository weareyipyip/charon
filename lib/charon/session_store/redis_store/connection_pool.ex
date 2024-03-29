if Code.ensure_loaded?(Redix) and Code.ensure_loaded?(:poolboy) do
  defmodule Charon.SessionStore.RedisStore.ConnectionPool do
    @moduledoc false
    use Supervisor

    @pool_name :charon_redisstore_pool
    @default_timeout 5000

    @type pool_status :: %{
            available_workers: integer,
            checked_out_workers: integer,
            checked_out_overflow_workers: integer,
            status: atom
          }

    @doc """
    Start the connection pool.

    ## Options
      - `:name` (default module name) under which the supervisor is registred
      - `:size` (default 10) total number of (local) normal workers
      - `:max_overflow` (default 5) max number of (local) extra workers in case of high load
      - `:redix_opts` passed to `Redix.start_link/1`

    The pool and its config options are local to the Elixir/OTP node,
    so if you use multiple nodes, the total connection count to Redis maxes out at
    `(size + max_overflow) * number_of_nodes`.
    """
    @spec start_link(nil | maybe_improper_list | map) :: :ignore | {:error, any} | {:ok, pid}
    def start_link(opts \\ []) do
      name = opts[:name] || __MODULE__
      size = opts[:size] || 10
      max_overflow = opts[:max_overflow] || 5
      redix_opts = opts[:redix_opts] || []

      init_arg = [size: size, max_overflow: max_overflow, redix_opts: redix_opts]
      Supervisor.start_link(__MODULE__, init_arg, name: name)
    end

    @doc """
    Returns the connection pool status.
    Total `non_overflow_workers = available_workers + checked_out_workers`.
    The total overflow worker count is not returned.
    """
    @spec status :: pool_status()
    def status() do
      {status, available, overflow_in_use, checked_out_workers} = :poolboy.status(@pool_name)

      %{
        status: status,
        available_workers: available,
        checked_out_overflow_workers: overflow_in_use,
        checked_out_workers: checked_out_workers
      }
    end

    @doc """
    Checkout a connection from the pool,
    execute `function` as a transaction,
    and return the connection to the pool.

    Note that `timeout` means the maximum wait for a connection to become available
    before raising, it does not limit how long the transaction may take.
    """
    @spec transaction((pid -> any), :infinity | non_neg_integer) :: any
    def transaction(function, timeout \\ @default_timeout) do
      :poolboy.transaction(@pool_name, function, timeout)
    end

    @doc """
    Checkout a connection from the pool.

    Note that `timeout` means the maximum wait for a connection to become available
    before raising, it does not limit how long the transaction may take.

    If you set `block` to `false`, the function will immediately return `:full` instead
    of waiting for `timeout` if no connection is available.
    """
    @spec checkout(:infinity | non_neg_integer, boolean) :: :full | pid
    def checkout(timeout \\ @default_timeout, block \\ true) do
      :poolboy.checkout(@pool_name, block, timeout)
    end

    @doc """
    Return a previously checked-out connection to the pool.
    """
    @spec checkin(pid) :: :ok
    def checkin(connection) do
      :poolboy.checkin(@pool_name, connection)
    end

    #############
    # Callbacks #
    #############

    @doc false
    @impl true
    def init(opts) do
      poolboy_config = [
        name: {:local, @pool_name},
        worker_module: Redix,
        size: opts[:size],
        max_overflow: opts[:max_overflow]
      ]

      [:poolboy.child_spec(@pool_name, poolboy_config, opts[:redix_opts])]
      |> Supervisor.init(strategy: :one_for_one)
    end
  end
end
