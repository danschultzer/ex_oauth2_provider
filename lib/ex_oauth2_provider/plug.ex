defmodule ExOauth2Provider.Plug do
  @moduledoc """
  ExOauth2Provider.Plug contains functions that assist with interacting with
  ExOauth2Provider via Plugs.
  ExOauth2Provider.Plug is not itself a plug.
  Use the helpers to look up current_token and current_resource.
  ## Example
      ExOauth2Provider.Plug.current_token(conn)
      ExOauth2Provider.Plug.current_resource(conn)
  """

  import ExOauth2Provider.Keys

  @doc """
  A simple check to see if a request is authenticated
  """
  @spec authenticated?(Plug.Conn.t) :: atom # boolean
  def authenticated?(conn), do: authenticated?(conn, :default)

  @doc """
  A simple check to see if a request is authenticated
  """
  @spec authenticated?(Plug.Conn.t, atom) :: atom # boolean
  def authenticated?(conn, type) do
    case current_token(conn, type) do
      nil -> false
      _ -> true
    end
  end

  @doc """
  Fetch the currently authenticated resource if loaded,
  optionally located at a key
  """
  @spec current_resource(Plug.Conn.t, atom) :: any | nil
  def current_resource(conn, the_key \\ :default) do
    conn
    |> current_token(the_key)
    |> ExOauth2Provider.repo.preload(:resource_owner)
    |> get_resource_owner
  end

  defp get_resource_owner(nil), do: nil
  defp get_resource_owner(access_token), do: Map.fetch!(access_token, :resource_owner)

  @doc """
  Fetch the currently verified token from the request.
  Optionally located at a key
  """
  @spec current_token(Plug.Conn.t, atom) :: String.t | nil
  def current_token(conn, the_key \\ :default) do
    conn.private[token_key(the_key)]
  end

  @doc false
  def set_current_token(conn, token, the_key \\ :default) do
    Plug.Conn.put_private(conn, token_key(the_key), token)
  end
end
