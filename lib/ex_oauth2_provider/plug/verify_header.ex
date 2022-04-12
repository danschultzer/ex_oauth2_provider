defmodule ExOauth2Provider.Plug.VerifyHeader do
  @moduledoc """
  Use this plug to authenticate a token contained in the header.
  You should set the value of the Authorization header to:
      Authorization: <token>

  ## Example
      plug ExOauth2Provider.Plug.VerifyHeader, otp_app: :my_app

  A "realm" can be specified when using the plug.
  Realms are like the name of the token and allow many tokens
  to be sent with a single request.

      plug ExOauth2Provider.Plug.VerifyHeader, otp_app: :my_app, realm: "Bearer"

  When a realm is not specified, the first authorization header
  found is used, and assumed to be a raw token

  #### example
      plug ExOauth2Provider.Plug.VerifyHeader, otp_app: :my_app

      # will take the first auth header
      # Authorization: <token>
  """

  alias Plug.Conn
  alias ExOauth2Provider.Config
  alias ExOauth2Provider.Plug

  @doc false
  @spec init(keyword()) :: keyword()
  def init(opts \\ []) do
    opts
    |> Keyword.get(:realm)
    |> maybe_set_realm_option(opts)
  end

  defp maybe_set_realm_option(nil, opts), do: opts

  defp maybe_set_realm_option(realm, opts) do
    realm = Regex.escape(realm)
    {:ok, realm_regex} = Regex.compile("#{realm}\:?\s+(.*)$", "i")

    Keyword.put(opts, :realm_regex, realm_regex)
  end

  @doc false
  @spec call(Conn.t(), keyword()) :: Conn.t()
  def call(conn, opts) do
    conn
    |> fetch_token(opts)
    |> verify_token(conn, opts)
  end

  defp fetch_token(conn, opts) do
    auth_header = Conn.get_req_header(conn, "authorization")

    opts
    |> Keyword.get(:realm_regex)
    |> do_fetch_token(auth_header)
  end

  defp do_fetch_token(_realm_regex, []), do: nil
  defp do_fetch_token(nil, [token | _tail]), do: String.trim(token)

  defp do_fetch_token(realm_regex, [token | tail]) do
    trimmed_token = String.trim(token)

    case Regex.run(realm_regex, trimmed_token) do
      [_, match] -> String.trim(match)
      _ -> do_fetch_token(realm_regex, tail)
    end
  end

  defp verify_token(nil, conn, _), do: conn
  defp verify_token("", conn, _), do: conn

  defp verify_token(token, conn, opts) do
    key = Keyword.get(opts, :key, :default)
    config = Keyword.take(opts, [:authenticate_token_with, :otp_app])

    access_token = Config.token_authenticator(config).(token, config)
    Plug.set_current_access_token(conn, access_token, key)
  end
end
