defmodule ExOauth2Provider.Applications do
  @moduledoc """
  The boundary for the applications system.
  """

  import Ecto.Query
  alias Ecto.{Changeset, Schema}
  alias ExOauth2Provider.{AccessTokens, Applications.Application, Config}

  @doc """
  Gets a single application by uid.

  Raises `Ecto.NoResultsError` if the Application does not exist.

  ## Examples

      iex> get_application!("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthApplication{}

      iex> get_application!("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      ** (Ecto.NoResultsError)

  """
  @spec get_application!(binary()) :: Application.t() | no_return
  def get_application!(uid) do
    ExOauth2Provider.repo.get_by!(Config.application(), uid: uid)
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
  @spec get_application_for!(Schema.t(), binary()) :: Application.t() | no_return
  def get_application_for!(resource_owner, uid) do
    ExOauth2Provider.repo.get_by!(Config.application(), owner_id: resource_owner.id, uid: uid)
  end

  @doc """
  Gets a single application by uid.

  ## Examples

      iex> get_application("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthApplication{}

      iex> get_application("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
  @spec get_application(binary()) :: Application.t() | nil
  def get_application(uid) do
    ExOauth2Provider.repo.get_by(Config.application(), uid: uid)
  end

  @doc """
  Gets a single application by uid and secret.

  ## Examples

      iex> get_application("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d", "SECRET")
      %OauthApplication{}

      iex> get_application("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc", "SECRET")
      nil

  """
  @spec get_application(binary(), binary()) :: Application.t() | nil
  def get_application(uid, secret) do
    ExOauth2Provider.repo.get_by(Config.application(), uid: uid, secret: secret)
  end

  @doc """
  Returns all applications for a owner.

  ## Examples

      iex> get_applications_for(resource_owner)
      [%OauthApplication{}, ...]

  """
  @spec get_applications_for(Schema.t()) :: [Application.t()]
  def get_applications_for(resource_owner) do
    Config.application()
    |> where([a], a.owner_id == ^resource_owner.id)
    |> ExOauth2Provider.repo.all()
  end

  @doc """
  Gets all authorized applications for a resource owner.

  ## Examples

      iex> get_authorized_applications_for(owner)
      [%OauthApplication{},...]
  """
  @spec get_authorized_applications_for(Schema.t()) :: [Application.t()]
  def get_authorized_applications_for(resource_owner) do
    application_ids =
      resource_owner
      |> AccessTokens.get_authorized_tokens_for()
      |> Enum.map(&Map.get(&1, :application_id))

    Config.application()
    |> where([a], a.id in ^application_ids)
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
  @spec create_application(Schema.t()) :: {:ok, Application.t()} | {:error, Changeset.t()}
  def create_application(owner, attrs \\ %{}) do
    Config.application()
    |> struct(owner: owner)
    |> Application.changeset(attrs)
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
  @spec update_application(Application.t(), map()) :: {:ok, Application.t()} | {:error, Changeset.t()}
  def update_application(application, attrs) do
    application
    |> Application.changeset(attrs)
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
  @spec delete_application(Application.t()) :: {:ok, Application.t()} | {:error, Changeset.t()}
  def delete_application(application) do
    ExOauth2Provider.repo.delete(application)
  end

  @doc """
  Revokes all access tokens for an application and resource owner.

  ## Examples

      iex> revoke_all_access_tokens_for(application, resource_owner)
      {:ok, [%OauthAccessToken{}]}

  """
  @spec revoke_all_access_tokens_for(Application.t(), Schema.t()) :: [AccessToken.t()]
  def revoke_all_access_tokens_for(application, resource_owner) do
    ExOauth2Provider.repo.transaction fn ->
      Config.access_token()
      |> where([a], a.resource_owner_id == ^resource_owner.id)
      |> where([a], a.application_id == ^application.id)
      |> where([o], is_nil(o.revoked_at))
      |> ExOauth2Provider.repo.all()
      |> Enum.map(&AccessTokens.revoke!/1)
    end
  end
end
