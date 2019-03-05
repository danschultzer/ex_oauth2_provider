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
  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @doc false
  @spec call(Conn.t(), keyword()) :: map()
  def call(conn, opts) do
    key = Keyword.get(opts, :key, :default)

    conn
    |> Plug.current_access_token(key)
    |> check_scopes(conn, opts)
    |> handle_error()
  end

  defp check_scopes(nil, conn, opts), do: {:error, conn, opts}
  defp check_scopes(token, conn, opts) do
    scopes_set = fetch_scopes(opts)

    case matches_any_scopes_set?(token, scopes_set) do
      true  -> {:ok, conn, opts}
      false -> {:error, conn, opts}
    end
  end

  defp fetch_scopes(opts) do
    fetch_scopes(opts, Keyword.get(opts, :one_of))
  end

  defp fetch_scopes(opts, nil), do: [Keyword.get(opts, :scopes)]
  defp fetch_scopes(_opts, scopes), do: scopes

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
    module = Keyword.get(opts, :handler, Plug.ErrorHandler)
    params = Map.put(params, :reason, :unauthorized)

    conn
    |> Conn.assign(:ex_oauth2_provider_failure, :unauthorized)
    |> Conn.halt()
    |> module.unauthorized(params)
  end
end
