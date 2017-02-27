defmodule ExOauth2Provider do
  @moduledoc """
  A module that provides OAuth 2 based server for Elixir applications.
  ## Configuration
      config :ex_oauth2_provider, ExOauth2Provider,
        repo: App.Repo,
        resource_owner_model: App.User
  """

  @config Application.get_env(:ex_oauth2_provider, ExOauth2Provider, [])
  @repo Keyword.get(@config, :repo)
  @resource_owner_model Keyword.get(@config, :resource_owner_model)

  if is_nil(@repo), do: raise "ExOauth2Provider requires a repo"
  if is_nil(@resource_owner_model), do: raise "ExOauth2Provider requires a resource owner (e.g. User)"

  @doc """
  Authenticate the token.
  """
  @spec authenticate_token(String.t) :: {:ok, map} |
                                        {:error, any}
  def authenticate_token(nil), do: {:error, :token_inaccessible}
  def authenticate_token(token) do
    case ExOauth2Provider.OauthAccessToken |> @repo.get_by(token: token) do
      nil -> {:error, :token_not_found}
      res -> case ExOauth2Provider.OauthAccessToken.is_accessible?(res) do
        true -> {:ok, res}
        _ -> {:error, :token_inaccessible}
      end
    end
  end

  @doc """
  Generate a random token.
  """
  def generate_token(opts \\ %{}) do
    generator_method = Map.get(opts, :generator, fn(string) -> Base.encode16(string, case: :lower) end)
    token_size = Map.get(opts, :size, 32)
    string = :crypto.strong_rand_bytes(token_size)

    generator_method.(string)
  end

  def resource_owner_model, do: @resource_owner_model
  def repo, do: @repo
end
