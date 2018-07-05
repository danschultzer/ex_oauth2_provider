defmodule ExOauth2Provider.OauthApplications do
  @moduledoc """
  The boundary for the OauthApplications system.
  """

  import Ecto.Query
  alias Ecto.{Changeset, Schema}
  alias ExOauth2Provider.{OauthApplications.OauthApplication,
                          OauthAccessTokens,
                          OauthAccessTokens.OauthAccessToken,
                          RedirectURI,
                          Utils}
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
  @spec get_application!(binary()) :: OauthApplication.t() | no_return
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
  @spec get_application_for!(Schema.t(), binary()) :: OauthApplication.t() | no_return
  def get_application_for!(resource_owner, uid) do
    clauses = OauthApplication
              |> Utils.belongs_to_clause(:owner, resource_owner)
              |> Keyword.put(:uid, uid)

    ExOauth2Provider.repo.get_by!(OauthApplication, clauses)
  end

  @doc """
  Gets a single application by uid.

  ## Examples

      iex> get_application("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthApplication{}

      iex> get_application("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
  @spec get_application(binary()) :: OauthApplication.t() | nil
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
  @spec get_application(binary(), binary()) :: OauthApplication.t() | nil
  def get_application(uid, secret) do
    ExOauth2Provider.repo.get_by(OauthApplication, uid: uid, secret: secret)
  end

  @doc """
  Returns all applications for a owner.

  ## Examples

      iex> get_applications_for(resource_owner)
      [%OauthApplication{}, ...]

  """
  @spec get_applications_for(Schema.t()) :: [OauthApplication.t()]
  def get_applications_for(resource_owner) do
    clause = Utils.belongs_to_clause(OauthApplication, :owner, resource_owner)

    OauthApplication
    |> where(^clause)
    |> ExOauth2Provider.repo.all()
  end

  @doc """
  Gets all authorized applications for a resource owner.

  ## Examples

      iex> get_authorized_applications_for(owner)
      [%OauthApplication{},...]
  """
  @spec get_authorized_applications_for(Schema.t()) :: [OauthApplication.t()]
  def get_authorized_applications_for(resource_owner) do
    %{owner_key: owner_key, related_key: related_key} = Utils.schema_association(OauthAccessToken, :application)

    application_ids = resource_owner
                      |> OauthAccessTokens.get_authorized_tokens_for()
                      |> Enum.map(&Map.get(&1, owner_key))

    OauthApplication
    |> where([o], field(o, ^related_key) in ^application_ids)
    |> ExOauth2Provider.repo.all()
  end

  @doc """
  Creates an application.

  ## Examples

      iex> create_application(user, %{name: "App", redirect_uri: "http://example.com"})
      {:ok, %OauthApplication{}}

      iex> create_application(user, %{name: ""})
      {:error, %Ecto.Changeset{}}

  """
  @spec create_application(Schema.t()) :: {:ok, OauthApplication.t()} | {:error, Changeset.t()}
  def create_application(owner, attrs \\ %{}) do
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
  @spec update_application(OauthApplication.t(), map()) :: {:ok, OauthApplication.t()} | {:error, Changeset.t()}
  def update_application(application, attrs) do
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
  @spec delete_application(OauthApplication.t()) :: {:ok, OauthApplication.t()} | {:error, Changeset.t()}
  def delete_application(application),
    do: ExOauth2Provider.repo.delete(application)

  @doc """
  Returns an `%Ecto.Changeset{}` for tracking application changes.

  ## Examples

      iex> change_application(application)
      %Ecto.Changeset{source: %OauthApplication{}}

  """
  @spec change_application(OauthApplication.t()) :: Changeset.t()
  def change_application(application),
    do: application_changeset(application, %{})

  @doc """
  Revokes all access tokens for an application and resource owner.

  ## Examples

      iex> revoke_all_access_tokens_for(application, resource_owner)
      {:ok, [%OauthAccessToken{}]}

  """
  @spec revoke_all_access_tokens_for(OauthApplication.t(), Schema.t()) :: [OauthAccessToken.t()]
  def revoke_all_access_tokens_for(application, resource_owner) do
    resource_owner_clause = Utils.belongs_to_clause(OauthAccessToken, :resource_owner, resource_owner)
    application_clause = Utils.belongs_to_clause(OauthAccessToken, :application, application)

    ExOauth2Provider.repo.transaction fn ->
      OauthAccessToken
      |> where(^resource_owner_clause)
      |> where(^application_clause)
      |> where([o], is_nil(o.revoked_at))
      |> ExOauth2Provider.repo.all()
      |> Enum.map(&OauthAccessTokens.revoke!/1)
    end
  end

  defp application_changeset(%OauthApplication{} = application, params) do
    application
    |> Changeset.cast(params, [:name, :secret, :redirect_uri, :scopes])
    |> Changeset.validate_required([:name, :uid, :redirect_uri])
    |> validate_secret_not_nil()
    |> validate_scopes()
    |> validate_redirect_uri()
    |> Changeset.unique_constraint(:uid)
  end

  defp validate_secret_not_nil(changeset) do
    case Changeset.get_field(changeset, :secret) do
      nil -> Changeset.add_error(changeset, :secret, "can't be blank")
      _   -> changeset
    end
  end

  defp new_application_changeset(%OauthApplication{} = application, owner, params) do
    application
    |> Changeset.cast(params, [:uid, :secret])
    |> put_uid()
    |> put_secret()
    |> put_scopes()
    |> Changeset.put_assoc(:owner, owner)
    |> Changeset.assoc_constraint(:owner)
    |> Changeset.apply_changes()
    |> application_changeset(params)
  end

  defp validate_redirect_uri(changeset) do
    url = Changeset.get_field(changeset, :redirect_uri) || ""

    url
    |> String.split()
    |> Enum.reduce(changeset, &validate_redirect_uri(&2, &1))
  end

  defp validate_redirect_uri(changeset, url) do
    url
    |> RedirectURI.validate
    |> case do
       {:error, error} -> Changeset.add_error(changeset, :redirect_uri, error)
       {:ok, _}        -> changeset
     end
  end

  defp put_uid(%{changes: %{uid: _}} = changeset), do: changeset
  defp put_uid(%{} = changeset) do
    Changeset.change(changeset, %{uid: Utils.generate_token()})
  end

  defp put_secret(%{changes: %{secret: _}} = changeset), do: changeset
  defp put_secret(%{} = changeset) do
    Changeset.change(changeset, %{secret: Utils.generate_token()})
  end
end
