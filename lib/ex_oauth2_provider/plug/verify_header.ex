defmodule ExOauth2Provider.Plug.VerifyHeader do
  @moduledoc """
  Use this plug to authenticate a token contained in the header.
  You should set the value of the Authorization header to:
      Authorization: <token>

  ## Example
      plug ExOauth2Provider.Plug.VerifyHeader

  A "realm" can be specified when using the plug.
  Realms are like the name of the token and allow many tokens
  to be sent with a single request.

      plug ExOauth2Provider.Plug.VerifyHeader, realm: "Bearer"

  When a realm is not specified, the first authorization header
  found is used, and assumed to be a raw token

  #### example
      plug ExOauth2Provider.Plug.VerifyHeader

      # will take the first auth header
      # Authorization: <token>
  """

  alias Plug.Conn
  alias ExOauth2Provider.Plug

  @doc false
  @spec init(Keyword.t()) :: map()
  def init(opts \\ []) do
    opts
    |> Enum.into(%{})
    |> set_realm_option()
  end

  @doc false
  defp set_realm_option(%{realm: nil} = opts), do: opts
  defp set_realm_option(%{realm: realm} = opts) do
    {:ok, realm_regex} = Regex.compile("#{realm}\:?\s+(.*)$", "i")

    Map.put(opts, :realm_regex, realm_regex)
  end
  defp set_realm_option(opts), do: opts

  @doc false
  @spec call(Conn.t(), map()) :: Conn.t()
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    conn
    |> fetch_token(opts)
    |> verify_token(conn, key)
  end

  @doc false
  defp verify_token(nil, conn, _), do: conn
  defp verify_token("", conn, _), do: conn
  defp verify_token(token, conn, key) do
    access_token = ExOauth2Provider.authenticate_token(token)
    Plug.set_current_access_token(conn, access_token, key)
  end

  @doc false
  defp fetch_token(conn, opts) do
    fetch_token(conn, opts, Conn.get_req_header(conn, "authorization"))
  end

  @doc false
  defp fetch_token(_, _, []), do: nil
  defp fetch_token(conn, %{realm_regex: realm_regex} = opts, [token|tail]) do
    trimmed_token = String.trim(token)
    case Regex.run(realm_regex, trimmed_token) do
      [_, match] -> String.trim(match)
      _          -> fetch_token(conn, opts, tail)
    end
  end
  defp fetch_token(_, _, [token|_tail]), do: String.trim(token)
end
