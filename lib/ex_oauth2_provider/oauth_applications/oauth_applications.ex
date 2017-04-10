defmodule ExOauth2Provider.OauthApplications do
  @moduledoc """
  The boundary for the OauthApplications system.
  """

  import Ecto.{Query, Changeset}, warn: false
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.OauthAccessTokens
  use ExOauth2Provider.Mixin.Scopes

  @doc """
  Gets a single application by uid.

  Raises `Ecto.NoResultsError` if the OauthApplication does not exist.

  ## Examples

      iex> get_application!("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthApplication{}

      iex> get_application!("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      ** (Ecto.NoResultsError)

  """
  def get_application!(uid) do
    ExOauth2Provider.repo.get_by!(OauthApplication, uid: uid)
  end


  @doc """
  Gets a single application for a resource owner.

  Raises `Ecto.NoResultsError` if the OauthApplication does not exist for resource owner.

  ## Examples

      iex> get_application_for!(owner, "c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthApplication{}

      iex> get_application_for!(owner, "75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      ** (Ecto.NoResultsError)

  """
  def get_application_for!(%{id: owner_id}, uid) do
    ExOauth2Provider.repo.get_by!(OauthApplication, uid: uid, owner_id: owner_id)
  end

  @doc """
  Gets a single application by uid.

  ## Examples

      iex> get_application("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthApplication{}

      iex> get_application("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
  def get_application(uid) do
    ExOauth2Provider.repo.get_by(OauthApplication, uid: uid)
  end

  @doc """
  Gets a single application by uid and secret.

  ## Examples

      iex> get_application("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d", "SECRET")
      %OauthApplication{}

      iex> get_application("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc", "SECRET")
      nil

  """
  def get_application(uid, secret) do
    ExOauth2Provider.repo.get_by(OauthApplication, uid: uid, secret: secret)
  end

  @doc """
  Returns all applications for a owner.

  ## Examples

      iex> get_applications_for(resource_owner)
      [%OauthApplications{}, ...]

  """
  def get_applications_for(%{id: owner_id}) do
    OauthApplication
    |> where([x], x.owner_id == ^owner_id)
    |> ExOauth2Provider.repo.all
  end

  @doc """
  Gets all authorized applications for a resource owner.

  ## Examples

      iex> get_authorized_applications_for(owner)
      [%OauthApplication{},...]
  """
  def get_authorized_applications_for(%{id: _} = resource_owner) do
    application_ids = resource_owner
                      |> OauthAccessTokens.get_active_tokens_for
                      |> Enum.map(fn(o) -> o.application_id end)

    OauthApplication
    |> where([o], o.id in ^application_ids)
    |> ExOauth2Provider.repo.all
  end

  @doc """
  Creates an application.

  ## Examples

      iex> create_application(user, %{name: "App", redirect_uri: "http://example.com"})
      {:ok, %OauthApplication{}}

      iex> create_application(user, %{name: ""})
      {:error, %Ecto.Changeset{}}

  """
  def create_application(%{id: _} = owner, attrs \\ %{}) do
    %OauthApplication{}
    |> new_application_changeset(owner, attrs)
    |> ExOauth2Provider.repo.insert()
  end

  @doc """
  Updates an application.

  ## Examples

      iex> update_application(application, %{name: "Updated App"})
      {:ok, %OauthApplication{}}

      iex> update_application(application, %{name: ""})
      {:error, %Ecto.Changeset{}}

  """
  def update_application(%OauthApplication{} = application, attrs) do
    application
    |> application_changeset(attrs)
    |> ExOauth2Provider.repo.update()
  end

  @doc """
  Deletes an application.

  ## Examples

      iex> delete_application(application)
      {:ok, %OauthApplication{}}

      iex> delete_application(application)
      {:error, %Ecto.Changeset{}}

  """
  def delete_application(%OauthApplication{} = application),
    do: ExOauth2Provider.repo.delete(application)

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking application changes.

  ## Examples

      iex> change_application(application)
      %Ecto.Changeset{source: %OauthApplication{}}

  """
  def change_application(%OauthApplication{} = application),
    do: application_changeset(application, %{})

  @doc """
  Revokes all access tokens for an application and resource owner.

  ## Examples

      iex> revoke_all_access_tokens_for(application, resource_owner)
      {:ok, nil}

  """
  def revoke_all_access_tokens_for(%OauthApplication{id: application_id}, %{id: resource_owner_id}) do
    ExOauth2Provider.repo.transaction fn ->
      OauthAccessTokens.OauthAccessToken
      |> where([o], o.resource_owner_id == ^resource_owner_id)
      |> where([o], o.application_id == ^application_id)
      |> where([o], is_nil(o.revoked_at))
      |> ExOauth2Provider.repo.all
      |> Enum.map(fn(o) -> OauthAccessTokens.revoke(o) end)
    end
  end

  defp application_changeset(%OauthApplication{} = application, params) do
    application
    |> cast(params, [:name, :secret, :redirect_uri, :scopes])
    |> validate_required([:name, :uid, :secret, :redirect_uri])
    |> validate_scopes
    |> validate_redirect_uri
    |> unique_constraint(:uid)
  end

  defp new_application_changeset(%OauthApplication{} = application, %{id: _} = owner, params) do
    application
    |> cast(params, [:uid, :secret])
    |> put_uid
    |> put_secret
    |> put_scopes
    |> put_assoc(:owner, owner)
    |> assoc_constraint(:owner)
    |> apply_changes
    |> application_changeset(params)
  end

  defp validate_redirect_uri(changeset) do
    url = get_field(changeset, :redirect_uri) || ""

    url
    |> String.split
    |> Enum.reduce(changeset, fn(url, changeset) ->
                                validate_redirect_uri(changeset, url)
                              end)
  end

  defp validate_redirect_uri(changeset, url) do
    url
    |> ExOauth2Provider.RedirectURI.validate
    |> case do
       {:error, error} -> add_error(changeset, :redirect_uri, error)
       {:ok, _}        -> changeset
     end
  end

  defp put_uid(%{changes: %{uid: _}} = changeset), do: changeset
  defp put_uid(%{} = changeset) do
    change(changeset, %{uid: ExOauth2Provider.Utils.generate_token})
  end

  defp put_secret(%{changes: %{secret: _}} = changeset), do: changeset
  defp put_secret(%{} = changeset) do
    change(changeset, %{secret: ExOauth2Provider.Utils.generate_token})
  end
end
