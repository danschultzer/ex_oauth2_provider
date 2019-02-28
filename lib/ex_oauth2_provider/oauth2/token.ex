defmodule ExOauth2Provider.Token do
  @moduledoc """
  Handler for dealing with generating access tokens.
  """
  alias ExOauth2Provider.{Config,
                          Token.Revoke,
                          Utils.Error}
  alias Ecto.Schema

  @doc """
  Grants an access token based on grant_type strategy.

  ## Example

      ExOauth2Provider.Token.authorize(resource_owner, %{
        "grant_type" => "invalid",
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret"
      })

  ## Response

      {:error, %{error: error, error_description: description}, http_status}
  """
  @spec grant(map()) :: {:ok, Schema.t()} | {:error, map(), term}
  def grant(request) do
    case validate_grant_type(request) do
      {:error, :invalid_grant_type} -> Error.unsupported_grant_type()
      {:error, :missing_grant_type} -> Error.invalid_request()
      {:ok, token_module}           -> token_module.grant(request)
    end
  end

  defp validate_grant_type(%{"grant_type" => grant_type}) do
    grant_type = String.to_atom(grant_type)

    Config.calculate_token_grant_types()
    |> Keyword.get(grant_type)
    |> case do
      nil          -> {:error, :invalid_grant_type}
      token_module -> {:ok, token_module}
    end
  end
  defp validate_grant_type(_), do: {:error, :missing_grant_type}

  @doc """
  Revokes an access token as per http://tools.ietf.org/html/rfc7009

  ## Example
      ExOauth2Provider.Token.revoke(resource_owner, %{
        "client_id" => "Jf5rM8hQBc",
        "client_secret" => "secret",
        "token" => "fi3S9u"
      })

  ## Response

      {:ok, %{}}
  """
  @spec revoke(map()) :: {:ok, Schema.t()} | {:error, map(), term()}
  def revoke(request), do: Revoke.revoke(request)
end
