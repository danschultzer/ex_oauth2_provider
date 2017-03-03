defmodule ExOauth2Provider.Plug.EnsureScopes do
  @moduledoc """
  Use this plug to ensure that there are the
  correct scopes on the token found on the connection.
  ### Example
      alias ExOauth2Provider.Plug.EnsureScopes
      # read and write scopes
      plug EnsureScopes, scopes: ~w(read write), handler: SomeMod,
      # item:read AND item:write scopes
      # AND :profile scope
      plug EnsureScopes, scopes: ~(item:read item:write profile)
      # iteam:read AND item: write scope
      # OR :profile for the default set
      plug EnsureScopes, one_of: [~(item:read item:write),
                                  ~(profile)]
      # item :read AND :write for the token located in the :secret location
      plug EnsureScopes, key: :secret,
                         scopes: ~(read :write)
     If the handler option is not passed, `ExOauth2Provider.Plug.ErrorHandler` will provide
     the default behavior.
  """

  require Logger
  import Plug.Conn

  def init(opts) do
    opts = Enum.into(opts, %{})
    key = Map.get(opts, :key, :default)
    handler = build_handler_tuple(opts)

    scopes_sets = case Map.get(opts, :one_of) do
      nil ->
        case Map.get(opts, :scopes) do
          nil -> []
          [] -> []
          single_set -> [single_set]
        end
      one_of ->
        one_of
    end

    %{
      handler: handler,
      key: key,
      scopes_sets: scopes_sets
    }
  end

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key)
    case ExOauth2Provider.Plug.current_token(conn, key) do
      nil -> handle_error(conn, opts)
      token ->
        if matches_any_scopes_set?(token, Map.get(opts, :scopes_sets)) do
          conn
        else
          handle_error(conn, opts)
        end
    end
  end

  defp matches_any_scopes_set?(_, []), do: true
  defp matches_any_scopes_set?(access_token, scopes_sets) do
    Enum.any?(scopes_sets, &matches_scopes?(access_token, &1))
  end

  defp matches_scopes?(access_token, required_scopes) do
    access_token
    |> ExOauth2Provider.Scopes.from_access_token
    |> ExOauth2Provider.Scopes.all?(required_scopes)
  end

  defp handle_error(%Plug.Conn{params: params} = conn, opts) do
    conn = conn |> assign(:ex_oauth2_provider_failure, :unauthorized) |> halt
    params = Map.merge(params, %{reason: :unauthorized})
    {mod, meth} = Map.get(opts, :handler)

    apply(mod, meth, [conn, params])
  end

  defp build_handler_tuple(%{handler: mod}) do
    {mod, :unauthorized}
  end
  defp build_handler_tuple(_) do
    {ExOauth2Provider.Plug.ErrorHandler, :unauthorized}
  end

end
