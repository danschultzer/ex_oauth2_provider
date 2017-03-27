defmodule ExOauth2Provider.OauthApplications do
  @moduledoc """
  The boundary for the OauthApplications system.
  """

  import Ecto.{Query, Changeset}, warn: false
  alias ExOauth2Provider.OauthApplications.OauthApplication

  @doc """
  Returns the list of applications.

  ## Examples

      iex> list_applications()
      [%OauthApplications{}, ...]

  """
  def list_applications,
    do: ExOauth2Provider.repo.all(OauthApplication)

  @doc """
  Gets a single application.

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
  Gets a single application.

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
  Creates a application.

  ## Examples

      iex> create_application(user, %{name: "App", redirect_uri: "http://example.com"})
      {:ok, %OauthApplication{}}

      iex> create_application(user, %{name: ""})
      {:error, %Ecto.Changeset{}}

  """
  def create_application(resource_owner, attrs \\ %{}) do
    %OauthApplication{}
    |> new_application_changeset(resource_owner, attrs)
    |> ExOauth2Provider.repo.insert()
  end

  @doc """
  Updates a application.

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
  Deletes a Application.

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

  defp application_changeset(%OauthApplication{} = application, params) do
    application
    |> cast(params, [:name, :secret, :redirect_uri, :scopes])
    |> validate_required([:resource_owner, :name, :uid, :secret, :redirect_uri])
    |> unique_constraint(:uid)
    |> validate_redirect_uri
  end

  defp new_application_changeset(%OauthApplication{} = application, resource_owner, params) do
    application
    |> cast(params, [:uid, :secret])
    |> put_uid
    |> put_secret
    |> put_assoc(:resource_owner, resource_owner)
    |> apply_changes
    |> application_changeset(params)
  end

  defp validate_redirect_uri(%{redirect_uri: redirect_uri} = changeset) do
    redirect_uri
    |> ExOauth2Provider.RedirectURI.validate()
    |> case do
      {:error, error} -> add_error(changeset, :redirect_uri, error)
      {:ok, _} -> changeset
    end
  end
  defp validate_redirect_uri(%{} = changeset), do: changeset

  defp put_uid(%{changes: %{uid: _}} = changeset), do: changeset
  defp put_uid(%{} = changeset) do
    change(changeset, %{uid: ExOauth2Provider.generate_token})
  end

  defp put_secret(%{changes: %{secret: _}} = changeset), do: changeset
  defp put_secret(%{} = changeset) do
    change(changeset, %{secret: ExOauth2Provider.generate_token})
  end

  # defp put_change_if_empty(%{} = changeset, field, value) do
  #   case get_stripped_value_from_field(changeset, field) do
  #     "" -> put_change(changeset, field, value)
  #     _  -> changeset
  #   end
  # end
  #
  # defp get_stripped_value_from_field(%{} = changeset, field) do
  #   changeset
  #   |> get_field(field)
  #   |> nil_to_string
  #   |> String.strip
  # end
  #
  # defp nil_to_string(value) do
  #   value || ""
  # end
end
