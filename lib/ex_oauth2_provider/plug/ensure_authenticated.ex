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
  import Plug.Conn

  @doc false
  def init(opts) do
    opts = Enum.into(opts, %{})
    handler = build_handler_tuple(opts)

    %{
      handler: handler,
      key: Map.get(opts, :key, :default)
    }
  end

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case ExOauth2Provider.Plug.authenticated?(conn, key) do
      true -> conn
      false -> handle_error(conn, {:error, :not_authenticated}, opts)
    end
  end

  defp handle_error(%Plug.Conn{params: params} = conn, reason, opts) do
    conn = conn |> assign(:ex_oauth2_provider_failure, reason) |> halt
    params = Map.merge(params, %{reason: reason})
    {mod, meth} = Map.get(opts, :handler)

    apply(mod, meth, [conn, params])
  end

  defp build_handler_tuple(%{handler: mod}) do
    {mod, :unauthenticated}
  end
  defp build_handler_tuple(_) do
    {ExOauth2Provider.Plug.ErrorHandler, :unauthenticated}
  end
end
