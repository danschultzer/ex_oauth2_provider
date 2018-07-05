defmodule ExOauth2Provider.Plug.ErrorHandler do
  @moduledoc """
  A default error handler that can be used for failed authentication
  """

  alias Plug.Conn

  @callback unauthenticated(Conn.t(), map()) :: Conn.t()
  @callback unauthorized(Conn.t(), map()) :: Conn.t()
  @callback no_resource(Conn.t(), map()) :: Conn.t()

  @doc false
  @spec unauthenticated(Conn.t(), map()) :: Conn.t()
  def unauthenticated(conn, _params) do
    respond(conn, response_type(conn), 401, "Unauthenticated")
  end

  @doc false
  @spec unauthorized(Conn.t(), map()) :: Conn.t()
  def unauthorized(conn, _params) do
    respond(conn, response_type(conn), 403, "Unauthorized")
  end

  @doc false
  @spec no_resource(Conn.t(), map()) :: Conn.t()
  def no_resource(conn, _params) do
    respond(conn, response_type(conn), 403, "Unauthorized")
  end

  @doc false
  @spec already_authenticated(Conn.t(), map()) :: Conn.t()
  def already_authenticated(conn, _params), do: Conn.halt(conn)

  defp respond(conn, :json, status, msg) do
    conn
    |> Conn.configure_session(drop: true)
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status, Jason.encode!(%{errors: [msg]}))
  rescue ArgumentError ->
    conn
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(status, Jason.encode!(%{errors: [msg]}))
  end

  defp respond(conn, :html, status, msg) do
    conn
    |> Conn.configure_session(drop: true)
    |> Conn.put_resp_content_type("text/plain")
    |> Conn.send_resp(status, msg)
  rescue ArgumentError ->
    conn
    |> Conn.put_resp_content_type("text/plain")
    |> Conn.send_resp(status, msg)
  end

  defp response_type(conn) do
    accept = accept_header(conn)

    case Regex.match?(~r/json/, accept) do
      true -> :json
      false -> :html
    end
  end

  defp accept_header(conn)  do
    conn
    |> Conn.get_req_header("accept")
    |> List.first()
    |> Kernel.||("")
  end
end
