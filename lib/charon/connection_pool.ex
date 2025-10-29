if Code.ensure_loaded?(:poolboy) do
  defmodule Charon.ConnectionPool do
    @moduledoc """
    This is basically an Elixir wrapper of `:poolboy`.
    It is used for `Charon.RedisClient` but can be used externally as well.
    """
    @default_timeout 5000

    @type pool_status :: %{
            available_workers: integer,
            checked_out_workers: integer,
            checked_out_overflow_workers: integer,
            status: atom
          }

    @type pool_opts :: [
            name: module(),
            worker: module(),
            worker_args: any(),
            size: pos_integer(),
            max_overflow: pos_integer()
          ]

    @doc """
    Start the connection pool.

    ## Options
      - `:worker` worker/child module
      - `:worker_args` options to initialize the worker/child module
      - `:name` of the connection pool
      - `:size` (default 10) total number of (local) normal workers
      - `:max_overflow` (default 5) max number of (local) extra workers in case of high load

    The pool and its config options are local to the Elixir/OTP node,
    so if you use multiple nodes, the total connection count maxes out at
    `(size + max_overflow) * number_of_nodes`.
    """
    @spec child_spec(pool_opts()) :: :supervisor.child_spec()
    def child_spec(opts) do
      name = Keyword.fetch!(opts, :name)
      worker = Keyword.fetch!(opts, :worker)
      worker_args = Keyword.fetch!(opts, :worker_args)
      size = opts[:size] || 10
      max_overflow = opts[:max_overflow] || 5

      poolboy_config = [
        name: {:local, name},
        worker_module: worker,
        size: size,
        max_overflow: max_overflow
      ]

      :poolboy.child_spec(name, poolboy_config, worker_args)
    end

    @doc """
    Returns the connection pool status.
    Total `non_overflow_workers = available_workers + checked_out_workers`.
    The total overflow worker count is not returned.
    """
    @spec status(:poolboy.pool()) :: pool_status()
    def status(pool_name) do
      {status, available, overflow_in_use, checked_out_workers} = :poolboy.status(pool_name)

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
    @spec transaction(:poolboy.pool(), (pid -> any), :infinity | non_neg_integer) :: any
    def transaction(pool_name, function, timeout \\ @default_timeout) do
      :poolboy.transaction(pool_name, function, timeout)
    end

    @doc """
    Checkout a connection from the pool.

    Note that `timeout` means the maximum wait for a connection to become available
    before raising, it does not limit how long the transaction may take.

    If you set `block` to `false`, the function will immediately return `:full` instead
    of waiting for `timeout` if no connection is available.
    """
    @spec checkout(:poolboy.pool(), :infinity | non_neg_integer, boolean) :: :full | pid
    def checkout(pool_name, timeout \\ @default_timeout, block \\ true) do
      :poolboy.checkout(pool_name, block, timeout)
    end

    @doc """
    Return a previously checked-out connection to the pool.
    """
    @spec checkin(:poolboy.pool(), pid) :: :ok
    def checkin(pool_name, connection) do
      :poolboy.checkin(pool_name, connection)
    end

    @doc false
    def generate(base_mod) do
      module_name = Module.concat(base_mod, ConnectionPool)

      quote generated: true,
            location: :keep,
            bind_quoted: [
              base_mod: base_mod,
              module_name: module_name,
              moddoc: @moduledoc,
              timeout: @default_timeout
            ] do
        defmodule module_name do
          @moduledoc moddoc
          @default_timeout timeout

          def child_spec(opts) do
            opts
            |> Keyword.put_new(:name, unquote(module_name))
            |> Charon.ConnectionPool.child_spec()
          end

          defdelegate status(pool_name \\ unquote(module_name)), to: Charon.ConnectionPool

          defdelegate transaction(
                        pool_name \\ unquote(module_name),
                        function,
                        timeout \\ @default_timeout
                      ),
                      to: Charon.ConnectionPool

          defdelegate checkout(
                        pool_name \\ unquote(module_name),
                        timeout \\ @default_timeout,
                        block \\ true
                      ),
                      to: Charon.ConnectionPool

          defdelegate checkin(pool_name \\ unquote(module_name), connection),
            to: Charon.ConnectionPool
        end
      end
      |> Code.compile_quoted()
    end
  end
end
