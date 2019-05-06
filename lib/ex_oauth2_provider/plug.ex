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

  alias ExOauth2Provider.{Keys, AccessTokens.AccessToken}
  alias Plug.Conn

  @doc """
  Check if a request is authenticated
  """
  @spec authenticated?(Conn.t(), atom()) :: boolean()
  def authenticated?(conn, type \\ :default) do
    case get_current_access_token(conn, type) do
      {:error, _error}     -> false
      {:ok, _access_token} -> true
    end
  end

  @doc """
  Fetch the currently authenticated resource if loaded,
  optionally located at a key
  """
  @spec current_resource_owner(Conn.t(), atom()) :: map() | nil
  def current_resource_owner(conn, the_key \\ :default) do
    conn
    |> current_access_token(the_key)
    |> case do
      nil          -> nil
      access_token -> access_token.resource_owner
    end
  end

  @doc """
  Fetch the currently verified token from the request.
  Optionally located at a key
  """
  @spec current_access_token(Conn.t(), atom()) :: AccessToken.t() | nil
  def current_access_token(conn, the_key \\ :default) do
    case get_current_access_token(conn, the_key) do
      {:error, _error}    -> nil
      {:ok, access_token} -> access_token
    end
  end

  @doc false
  @spec get_current_access_token(Conn.t(), atom()) :: {:ok, AccessToken.t()} | {:error, term()}
  def get_current_access_token(conn, the_key \\ :default) do
    case conn.private[Keys.access_token_key(the_key)] do
      {:ok, access_token} -> {:ok, access_token}
      {:error, error}     -> {:error, error}
      _                   -> {:error, :no_session}
    end
  end

  @doc false
  @spec set_current_access_token(Conn.t(), {:ok, map()} | {:error, any()}, atom()) :: Conn.t()
  def set_current_access_token(conn, access_token, the_key \\ :default) do
    Conn.put_private(conn, Keys.access_token_key(the_key), access_token)
  end
end
