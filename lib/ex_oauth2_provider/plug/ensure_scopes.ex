defmodule ExOauth2Provider.Plug.EnsureScopes do
  @moduledoc """
  Use this plug to ensure that there are the correct scopes on
  the token found on the connection.

  ### Example
      alias ExOauth2Provider.Plug.EnsureScopes

      # With custom handler
      plug EnsureScopes, scopes: ~w(read write), handler: SomeMod,

      # item:read AND item:write scopes AND :profile scope
      plug EnsureScopes, scopes: ~(item:read item:write profile)

      # iteam:read AND item: write scope OR :profile for the default set
      plug EnsureScopes, one_of: [~(item:read item:write),
                                  ~(profile)]

      # item :read AND :write for the token located in the :secret location
      plug EnsureScopes, key: :secret, scopes: ~(read :write)

     If the handler option is not passed, `ExOauth2Provider.Plug.ErrorHandler`
     will provide the default behavior.
  """

  require Logger

  alias Plug.Conn
  alias ExOauth2Provider.{Plug, Scopes}

  @doc false
  @spec init(Keyword.t()) :: map()
  def init(opts) do
    opts = Enum.into(opts, %{})
    key = Map.get(opts, :key, :default)
    handler = build_handler_tuple(opts)

    %{handler: handler,
      key: key,
      scopes_sets: scopes_sets(opts)}
  end

  @doc false
  defp scopes_sets(%{one_of: one_of}), do: one_of
  defp scopes_sets(%{scopes: single_set}), do: [single_set]
  defp scopes_sets(_), do: nil

  @doc false
  @spec call(Conn.t(), map()) :: map()
  def call(conn, opts) do
    conn
    |> Plug.current_access_token(Map.get(opts, :key))
    |> check_scopes(conn, opts)
    |> handle_error()
  end

  defp check_scopes(nil, conn, opts), do: {:error, conn, opts}
  defp check_scopes(token, conn, opts) do
    scopes_set = Map.get(opts, :scopes_sets)

    case matches_any_scopes_set?(token, scopes_set) do
      true  -> {:ok, conn, opts}
      false -> {:error, conn, opts}
    end
  end

  defp matches_any_scopes_set?(_, []), do: true
  defp matches_any_scopes_set?(access_token, scopes_sets) do
    Enum.any?(scopes_sets, &matches_scopes?(access_token, &1))
  end

  defp matches_scopes?(access_token, required_scopes) do
    access_token
    |> Scopes.from_access_token()
    |> Scopes.all?(required_scopes)
  end

  defp handle_error({:ok, conn, _}), do: conn
  defp handle_error({:error, %Conn{params: params} = conn, opts}) do
    conn = conn
           |> Conn.assign(:ex_oauth2_provider_failure, :unauthorized)
           |> Conn.halt()
    params = Map.merge(params, %{reason: :unauthorized})
    {mod, meth} = Map.get(opts, :handler)

    apply(mod, meth, [conn, params])
  end

  defp build_handler_tuple(%{handler: mod}), do: {mod, :unauthorized}
  defp build_handler_tuple(_), do: {Plug.ErrorHandler, :unauthorized}
end
