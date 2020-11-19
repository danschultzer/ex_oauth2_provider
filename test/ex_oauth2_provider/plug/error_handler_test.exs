defmodule ExOauth2Provider.Plug.ErrorHandlerTest do
  @moduledoc false
  use ExUnit.Case, async: true
  use Plug.Test

  alias ExOauth2Provider.Plug.ErrorHandler

  setup do
    conn = conn(:get, "/foo")
    {:ok, %{conn: conn}}
  end

  describe "unauthenticated/2" do
    test "with text/html accept", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "text/html")
        |> ErrorHandler.unauthenticated(%{})

      assert conn.status == 401
      assert content_type(conn.resp_headers) =~ "text/plain"
      assert conn.resp_body == "Unauthenticated"
    end

    test "with application/json accept", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> ErrorHandler.unauthenticated(%{})

      assert conn.status == 401
      assert content_type(conn.resp_headers) =~ "application/json"
      assert conn.resp_body == Jason.encode!(%{errors: ["Unauthenticated"]})
    end

    test "with no accept header", %{conn: conn} do
      conn = ErrorHandler.unauthenticated(conn, %{})

      assert conn.status == 401
      assert content_type(conn.resp_headers) =~ "text/plain"
      assert conn.resp_body == "Unauthenticated"
    end
  end

  describe "unauthorized/2" do
    test "with text/html accept", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "text/html")
        |> ErrorHandler.unauthorized(%{})

      assert conn.status == 403
      assert content_type(conn.resp_headers) =~ "text/plain"
      assert conn.resp_body == "Unauthorized"
    end

    test "with application/json accept", %{conn: conn} do
      conn =
        conn
        |> put_req_header("accept", "application/json")
        |> ErrorHandler.unauthorized(%{})

      assert conn.status == 403
      assert content_type(conn.resp_headers) =~ "application/json"
      assert conn.resp_body == Jason.encode!(%{errors: ["Unauthorized"]})
    end

    test "with no accept header", %{conn: conn} do
      conn = ErrorHandler.unauthorized(conn, %{})

      assert conn.status == 403
      assert content_type(conn.resp_headers) =~ "text/plain"
      assert conn.resp_body == "Unauthorized"
    end
  end

  describe "already_authenticated/2" do
    test "halts the conn", %{conn: conn} do
      conn = ErrorHandler.already_authenticated(conn, %{})

      assert conn.halted
    end
  end

  defp content_type(headers) do
    headers
    |> Enum.filter(fn {k, _} -> k == "content-type" end)
    |> Enum.map(fn {_, v} -> v end)
    |> List.first()
  end
end
