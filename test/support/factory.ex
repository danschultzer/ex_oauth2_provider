defmodule ExOauth2Provider.Factory do
  @moduledoc """
  Generates factories
  """

  config = Application.get_env(:ex_oauth2_provider, ExOauth2Provider, [])

  @repo Keyword.get(config, :repo)
  @resource_owner_model Keyword.get(config, :resource_owner_model)
  @access_token ExOauth2Provider.OauthAccessToken

  use ExMachina.Ecto, repo: @repo

  def access_token_factory do
    %@access_token{
      scopes: "read,write"
    }
  end

  def user_factory do
    %@resource_owner_model{
      email: sequence(:email, &"foo-#{&1}@example.com")
    }
  end

  def access_token_with_user(params \\ %{}) do
    user = insert(:user)

    # Inserting and changing inserted_at timestamp
    attrs = params_for(:access_token, Map.merge(%{resource_owner_id: user.id}, params))
    {_, access_token} = @repo.insert(@access_token.create_changeset(%@access_token{}, attrs))

    {user, access_token}
  end

  def update_access_token_inserted_at(access_token, amount, units \\ :second) do
    inserted_at = access_token.inserted_at |> NaiveDateTime.add(amount, units)
    Ecto.Changeset.change(access_token, inserted_at: inserted_at)
      |> @repo.update!
  end
end
