defmodule ExOauth2Provider.Plug.ErrorHandler do
  @moduledoc """
  A default error handler that can be used for failed authentication
  """

  @callback unauthenticated(Plug.Conn.t, map) :: Plug.Conn.t
  @callback unauthorized(Plug.Conn.t, map) :: Plug.Conn.t
  @callback no_resource(Plug.Conn.t, map) :: Plug.Conn.t

  import Plug.Conn

  @doc false
  @spec unauthenticated(Plug.Conn.t, map) :: Plug.Conn.t
  def unauthenticated(conn, _params) do
    respond(conn, response_type(conn), 401, "Unauthenticated")
  end

  @doc false
  @spec unauthorized(Plug.Conn.t, map) :: Plug.Conn.t
  def unauthorized(conn, _params) do
    respond(conn, response_type(conn), 403, "Unauthorized")
  end

  @doc false
  @spec no_resource(Plug.Conn.t, map) :: Plug.Conn.t
  def no_resource(conn, _params) do
    respond(conn, response_type(conn), 403, "Unauthorized")
  end

  @doc false
  @spec already_authenticated(Plug.Conn.t, map) :: Plug.Conn.t
  def already_authenticated(conn, _params), do: halt(conn)

  defp respond(conn, :json, status, msg) do
    try do
      conn
      |> configure_session(drop: true)
      |> put_resp_content_type("application/json")
      |> send_resp(status, Poison.encode!(%{errors: [msg]}))
    rescue ArgumentError ->
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, Poison.encode!(%{errors: [msg]}))
    end
  end

  defp respond(conn, :html, status, msg) do
    try do
      conn
      |> configure_session(drop: true)
      |> put_resp_content_type("text/plain")
      |> send_resp(status, msg)
    rescue ArgumentError ->
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(status, msg)
    end
  end

  defp response_type(conn) do
    accept = accept_header(conn)

    case Regex.match?(~r/json/, accept) do
      true -> :json
      false -> :html
    end
  end

  defp accept_header(conn)  do
    value = conn
      |> get_req_header("accept")
      |> List.first()

    value || ""
  end
end
