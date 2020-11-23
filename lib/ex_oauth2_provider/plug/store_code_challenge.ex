defmodule ExOauth2Provider.Plug.StoreCodeChallenge do
  @moduledoc """
  PKCE requirement support: stores the code_challenge using :pkce_module from config
  """
  alias ExOauth2Provider.Config

  def init(opts), do: opts

  def call(conn, opts) do
    config = Keyword.take(opts, [:otp_app])
    ensure_code_challenge(conn, config)
  end

  defp ensure_code_challenge(conn, config) do
    case conn.params do
      %{"client_id" => client_id, "code_challenge" => code_challenge} ->
        Config.pkce_module(config).store(client_id, code_challenge)
        conn

      _ ->
        conn
    end
  end
end
