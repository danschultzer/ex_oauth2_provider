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

  defp validate_grant_type(%{"grant_type" => type}) do
    type
    |> fetch_module()
    |> case do
      nil -> {:error, :invalid_grant_type}
      mod -> {:ok, mod}
    end
  end
  defp validate_grant_type(_), do: {:error, :missing_grant_type}

  defp fetch_module(type) do
    Config.grant_flows()
    |> grant_type_can_be_used?(type)
    |> case do
      true  -> grant_type_to_mod(type)
      false -> nil
    end
  end

  defp grant_type_can_be_used?(_, "refresh_token"),
    do: Config.use_refresh_token?()
  defp grant_type_can_be_used?(_, "password"),
    do: not is_nil(Config.password_auth())
  defp grant_type_can_be_used?(grant_flows, grant_type) do
    Enum.member?(grant_flows, grant_type)
  end

  defp grant_type_to_mod("authorization_code"), do: ExOauth2Provider.Token.AuthorizationCode
  defp grant_type_to_mod("client_credentials"), do: ExOauth2Provider.Token.ClientCredentials
  defp grant_type_to_mod("password"), do: ExOauth2Provider.Token.Password
  defp grant_type_to_mod("refresh_token"), do: ExOauth2Provider.Token.RefreshToken
  defp grant_type_to_mod(_), do: nil

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
