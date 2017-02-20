defmodule ExOauth2Provider.Plug do

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
      token -> true
    end
  end

  @doc """
  Fetch the currently authenticated resource if loaded,
  optionally located at a key
  """
  @spec current_resource(Plug.Conn.t, atom) :: any | nil
  def current_resource(conn, the_key \\ :default) do
    conn.private[resource_key(the_key)]
  end

  @doc false
  def set_current_resource(conn, resource, the_key \\ :default) do
    Plug.Conn.put_private(conn, resource_key(the_key), resource)
  end

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
