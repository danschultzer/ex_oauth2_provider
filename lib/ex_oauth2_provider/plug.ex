defmodule ExOauth2Provider.Plug do
  @moduledoc """
  ExOauth2Provider.Plug contains functions that assist with interacting with
  ExOauth2Provider via Plugs.

  ExOauth2Provider.Plug is not itself a plug.

  Use the helpers to look up current_access_token and current_resource_owner.

  ## Example
      ExOauth2Provider.Plug.current_access_token(conn)
      ExOauth2Provider.Plug.current_resource_owner(conn)
  """

  import ExOauth2Provider.Keys

  @doc """
  Check if a request is authenticated
  """
  @spec authenticated?(Plug.Conn.t) :: atom # boolean
  def authenticated?(conn), do: authenticated?(conn, :default)

  @doc """
  Check if a request is authenticated
  """
  @spec authenticated?(Plug.Conn.t, atom) :: atom # boolean
  def authenticated?(conn, type) do
    case get_current_access_token(conn, type) do
      {:error, _} -> false
      {:ok, _}    -> true
    end
  end

  @doc """
  Fetch the currently authenticated resource if loaded,
  optionally located at a key
  """
  @spec current_resource_owner(Plug.Conn.t, atom) :: any | nil
  def current_resource_owner(conn, the_key \\ :default) do
    case current_access_token(conn, the_key) do
      nil          -> nil
      access_token -> access_token.resource_owner
    end
  end

  @doc """
  Fetch the currently verified token from the request.
  Optionally located at a key
  """
  @spec current_access_token(Plug.Conn.t, atom) :: String.t | nil
  def current_access_token(conn, the_key \\ :default) do
    case get_current_access_token(conn, the_key) do
      {:ok, access_token} -> access_token
      {:error, _}         -> nil
    end
  end

  @doc false
  def get_current_access_token(conn, the_key \\ :default) do
    case conn.private[access_token_key(the_key)] do
      {:ok, _} = token    -> token
      {:error, _} = token -> token
      _                   -> {:error, :no_session}
    end
  end

  @doc false
  def set_current_access_token(conn, access_token, the_key \\ :default) do
    Plug.Conn.put_private(conn, access_token_key(the_key), access_token)
  end
end
