defmodule ExOauth2Provider.Plug.EnsureAuthenticated do
  @moduledoc """
  This plug ensures that the request has been authenticated with an access token.

  If one is not found, the `unauthenticated/2` function is invoked with the
  `Plug.Conn.t` object and its params.

  ## Example

      # Will call the unauthenticated/2 function on your handler
      plug ExOauth2Provider.Plug.EnsureAuthenticated, handler: SomeModule

      # look in the :secret location.  You can also do simple claim checks:
      plug ExOauth2Provider.Plug.EnsureAuthenticated, handler: SomeModule, key: :secret

      plug ExOauth2Provider.Plug.EnsureAuthenticated, handler: SomeModule, typ: "access"

  If the handler option is not passed, `ExOauth2Provider.Plug.ErrorHandler` will provide
  the default behavior.
  """
  alias Plug.Conn
  alias ExOauth2Provider.Plug

  @doc false
  @spec init(Keyword.t) :: map()
  def init(opts) do
    opts = Enum.into(opts, %{})
    handler = build_handler_tuple(opts)

    %{handler: handler,
      key: Map.get(opts, :key, :default)}
  end

  @doc false
  @spec call(Conn.t(), map()) :: map()
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    conn
    |> get_authentication(key, opts)
    |> handle_authentication()
  end

  @doc false
  @spec get_authentication(Conn.t(), atom(), map()) :: {Conn.t(), {:ok, binary()} | {:error, term()}}
  defp get_authentication(conn, key, opts),
    do: {conn, Plug.get_current_access_token(conn, key), opts}

  @doc false
  defp handle_authentication({conn, {:ok, _}, _}), do: conn
  defp handle_authentication({conn, {:error, reason}, opts}),
    do: handle_error(conn, reason, opts)

  @doc false
  defp handle_error(%Conn{params: params} = conn, reason, opts) do
    conn = conn
           |> Conn.assign(:ex_oauth2_provider_failure, reason)
           |> Conn.halt()
    params = Map.merge(params, %{reason: reason})
    {module, method} = Map.get(opts, :handler)

    apply(module, method, [conn, params])
  end

  @doc false
  defp build_handler_tuple(%{handler: mod}) do
    {mod, :unauthenticated}
  end
  defp build_handler_tuple(_) do
    {ExOauth2Provider.Plug.ErrorHandler, :unauthenticated}
  end
end
