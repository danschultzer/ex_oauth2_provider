defmodule ExOauth2Provider.AccessTokens do
  @moduledoc """
  Ecto schema for oauth access tokens
  """

  import Ecto.Query
  alias ExOauth2Provider.Mixin.{Expirable, Revocable, Scopes}
  alias ExOauth2Provider.{AccessTokens.AccessToken, Applications.Application, Config}
  alias ExOauth2Provider.Scopes, as: ScopesUtils
  alias ExOauth2Provider.Schema, as: SchemaHelpers
  alias Ecto.{Changeset, Schema}

  defdelegate revoke!(token), to: Revocable
  defdelegate revoke(token), to: Revocable
  defdelegate is_expired?(token), to: Expirable
  defdelegate is_revoked?(token), to: Revocable

  @doc """
  Gets a single access token.

  ## Examples

      iex> get_by_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
  @spec get_by_token(binary()) :: AccessToken.t() | nil
  def get_by_token(token) do
    ExOauth2Provider.repo.get_by(Config.access_token(), token: token)
  end

  @doc """
  Gets an access token by the refresh token.

  ## Examples

      iex> get_by_refresh_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_refresh_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil
  """
  @spec get_by_refresh_token(binary()) :: AccessToken.t() | nil
  def get_by_refresh_token(refresh_token) do
    ExOauth2Provider.repo.get_by(Config.access_token(), refresh_token: refresh_token)
  end

  @doc """
  Gets an access token by the refresh token belonging to an application.

  ## Examples

      iex> get_by_refresh_token_for(application, "c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_refresh_token_for(application, "75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil
  """
  @spec get_by_refresh_token_for(Application.t(), binary()) :: AccessToken.t() | nil
  def get_by_refresh_token_for(application, refresh_token) do
    ExOauth2Provider.repo.get_by(Config.access_token(), application_id: application.id, refresh_token: refresh_token)
  end

  @doc """
  Gets the most recent, acccessible, matching access token for a resource owner.

  ## Examples

      iex> get_matching_token_for(resource_owner, application, "read write")
      %OauthAccessToken{}

      iex> get_matching_token_for(resource_owner, application, "read invalid")
      nil

  """
  @spec get_matching_token_for(Schema.t() | nil, Application.t(), binary()) :: AccessToken.t() | nil
  def get_matching_token_for(nil, application, scopes) do
    Config.access_token()
    |> scope_belongs_to(:resource_owner_id, nil)
    |> scope_belongs_to(:application_id, application)
    |> load_matching_token_for(scopes)
  end
  def get_matching_token_for(resource_owner, application, scopes) do
    Config.access_token()
    |> scope_belongs_to(:resource_owner_id, resource_owner)
    |> scope_belongs_to(:application_id, application)
    |> load_matching_token_for(scopes)
  end

  defp load_matching_token_for(queryable, scopes) do
    now = SchemaHelpers.__timestamp_for__(Config.access_token(), :inserted_at)

    queryable
    |> where([a], is_nil(a.revoked_at))
    |> where([a], is_nil(a.expires_in) or datetime_add(a.inserted_at, a.expires_in, "second") > ^now)
    |> order_by([a], desc: a.inserted_at, desc: :id)
    |> ExOauth2Provider.repo.all()
    |> Enum.filter(&is_accessible?/1)
    |> check_matching_scopes(scopes)
  end

  defp check_matching_scopes(tokens, scopes) when is_list(tokens) do
    Enum.find(tokens, nil, &check_matching_scopes(&1, scopes))
  end
  defp check_matching_scopes(nil, _), do: nil
  defp check_matching_scopes(token, scopes) do
    token_scopes   = ScopesUtils.to_list(token.scopes)
    request_scopes = ScopesUtils.to_list(scopes)

    case ScopesUtils.equal?(token_scopes, request_scopes) do
      true -> token
      _    -> nil
    end
  end

  @doc """
  Gets all authorized access tokens for resource owner.

  ## Examples

      iex> get_authorized_tokens_for(resource_owner)
      [%OauthAccessToken{}, ...]
  """
  @spec get_authorized_tokens_for(Schema.t()) :: [AccessToken.t()]
  def get_authorized_tokens_for(resource_owner) do
    Config.access_token()
    |> where([a], a.resource_owner_id == ^resource_owner.id)
    |> where([a], is_nil(a.revoked_at))
    |> ExOauth2Provider.repo.all()
  end

  @doc """
  Creates an access token.

  ## Examples

      iex> create_token(resource_owner, %{application: application, scopes: "read write"})
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{scopes: "read write"})
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{expires_in: "invalid"})
      {:error, %Ecto.Changeset{}}
  """
  @spec create_token(Schema.t() | nil, map()) :: {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def create_token(resource_owner, attrs \\ %{}) do
    struct =
      attrs
      |> Map.take([:application])
      |> Map.put(:resource_owner, resource_owner)

    Config.access_token()
    |> struct(struct)
    |> do_create_token(attrs)
  end

  defp do_create_token(access_token, attrs) do
    access_token
    |> AccessToken.changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end

  @doc """
  Creates an application access token.

  ## Examples

      iex> create_application_token(application, %{scopes: "read write"})
      {:ok, %OauthAccessToken{}}
  """
  @spec create_application_token(Schema.t() | nil, map()) :: {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def create_application_token(application, attrs \\ %{}) do
    Config.access_token()
    |> struct(application: application)
    |> do_create_token(attrs)
  end

  @doc """
  Gets existing access token or creates a new one with supplied attributes.

  ## Examples

      iex> get_or_create_token(application, scopes, attrs)
      {:ok, %OauthAccessToken{}}

      iex> get_or_create_token(user, application, scopes, attrs)
      {:ok, %OauthAccessToken{}}

      iex> get_or_create_token(user, application, scopes, attrs)
      {:error, %Ecto.Changeset{}}

  """
  @spec get_or_create_token(Schema.t(), Application.t() | nil, binary() | nil, map()) :: {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def get_or_create_token(resource_owner, application, scopes, attrs) do
    attrs = Map.merge(%{scopes: scopes, application: application}, attrs)
    scopes = maybe_build_scopes(application, scopes)

    resource_owner
    |> get_matching_token_for(application, scopes)
    |> case do
      nil ->
        attrs = Map.merge(%{expires_in: Config.access_token_expires_in()}, attrs)

        create_token(resource_owner, attrs)

      access_token ->
        {:ok, access_token}
    end
  end

  defp maybe_build_scopes(_application, scopes) when is_binary(scopes), do: scopes
  defp maybe_build_scopes(%{scopes: server_scopes}, nil), do: Scopes.parse_default_scope_string(server_scopes)
  defp maybe_build_scopes(_application, nil), do: Scopes.parse_default_scope_string(nil)

  @doc """
  Gets existing application access token or creates a new one with supplied attributes.

  ## Examples

      iex> get_or_create_application_token(application, scopes, attrs)
      {:ok, %OauthAccessToken{}}
  """
  @spec get_or_create_application_token(Application.t(), binary() | nil, map()) :: {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def get_or_create_application_token(application, scopes, attrs) do
    get_or_create_token(nil, application, scopes, attrs)
  end

  @doc """
  Checks if an access token can be accessed.

  ## Examples

      iex> is_accessible?(token)
      true

      iex> is_accessible?(inaccessible_token)
      false

  """
  @spec is_accessible?(AccessToken.t() | nil) :: boolean()
  def is_accessible?(nil), do: false
  def is_accessible?(token) do
    !is_expired?(token) and !is_revoked?(token)
  end

  @doc """
  Gets an old access token by previous refresh token.

  ## Examples

      iex> get_by_previous_refresh_token_for(new_access_token)
      %OauthAccessToken{}

      iex> get_by_previous_refresh_token_for(new_access_token)
      nil
  """
  @spec get_by_previous_refresh_token_for(AccessToken.t()) :: AccessToken.t() | nil
  def get_by_previous_refresh_token_for(%{previous_refresh_token: nil}), do: nil
  def get_by_previous_refresh_token_for(%{previous_refresh_token: ""}), do: nil
  def get_by_previous_refresh_token_for(%{previous_refresh_token: previous_refresh_token, resource_owner_id: resource_owner_id, application_id: application_id}) do
    Config.access_token()
    |> scope_belongs_to(:application_id, application_id)
    |> where([a], a.resource_owner_id == ^resource_owner_id)
    |> where([a], a.refresh_token == ^previous_refresh_token)
    |> limit(1)
    |> ExOauth2Provider.repo.one()
  end

  defp scope_belongs_to(queryable, belongs_to_column, nil) do
    where(queryable, [x], is_nil(field(x, ^belongs_to_column)))
  end
  defp scope_belongs_to(queryable, belongs_to_column, %{id: id}) do
    scope_belongs_to(queryable, belongs_to_column, id)
  end
  defp scope_belongs_to(queryable, belongs_to_column, id) do
    where(queryable, [x], field(x, ^belongs_to_column) == ^id)
  end

  @doc """
  Revokes token with `refresh_token` equal to
  `previous_refresh_token` and clears `:previous_refresh_token`
  attribute.

  ## Examples

      iex> revoke_previous_refresh_token(data)
      {:ok, %OauthAccessToken{}}

      iex> revoke_previous_refresh_token(invalid_data)
      {:error, %Ecto.Changeset{}}
  """
  @spec revoke_previous_refresh_token(AccessToken.t()) :: {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def revoke_previous_refresh_token(%{previous_refresh_token: ""} = access_token), do: {:ok, access_token}
  def revoke_previous_refresh_token(%{previous_refresh_token: nil} = access_token), do: {:ok, access_token}
  def revoke_previous_refresh_token(access_token) do
    access_token
    |> get_by_previous_refresh_token_for()
    |> revoke()

    reset_previous_refresh_token(access_token)
  end

  defp reset_previous_refresh_token(access_token) do
    access_token
    |> Changeset.change(previous_refresh_token: "")
    |> ExOauth2Provider.repo.update()
  end
end
