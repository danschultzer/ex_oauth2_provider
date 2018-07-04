defmodule ExOauth2Provider.OauthAccessTokens do
  @moduledoc """
  Ecto schema for oauth access tokens
  """

  import Ecto.{Query, Changeset}, warn: false
  use ExOauth2Provider.Mixin.Expirable
  use ExOauth2Provider.Mixin.Revocable
  use ExOauth2Provider.Mixin.Scopes
  alias ExOauth2Provider.OauthAccessTokens.OauthAccessToken
  alias ExOauth2Provider.OauthApplications.OauthApplication
  alias ExOauth2Provider.Scopes
  alias Ecto.{Changeset, Schema}

  @doc """
  Gets a single access token.

  ## Examples

      iex> get_by_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
  @spec get_by_token(binary()) :: OauthAccessToken.t() | nil
  def get_by_token(token) do
    ExOauth2Provider.repo.get_by(OauthAccessToken, token: token)
  end

  @doc """
  Gets an access token by the refresh token.

  ## Examples

      iex> get_by_refresh_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_refresh_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil
  """
  @spec get_by_refresh_token(binary()) :: OauthAccessToken.t() | nil
  def get_by_refresh_token(refresh_token) do
    ExOauth2Provider.repo.get_by(OauthAccessToken, refresh_token: refresh_token)
  end

  @doc """
  Gets an access token by the refresh token belonging to an application.

  ## Examples

      iex> get_by_refresh_token_for(application, "c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_refresh_token_for(application, "75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil
  """
  @spec get_by_refresh_token_for(OauthApplication.t(), binary()) :: OauthAccessToken.t() | nil
  def get_by_refresh_token_for(application, refresh_token) do
    clauses = OauthAccessToken
    |> ExOauth2Provider.Utils.belongs_to_clause(:application, application)
    |> Keyword.put(:refresh_token, refresh_token)

    ExOauth2Provider.repo.get_by(OauthAccessToken, clauses)
  end

  @doc """
  Gets the most recent, acccessible, matching access token for a resource owner.

  ## Examples

      iex> get_matching_token_for(resource_owner, application, "read write")
      %OauthAccessToken{}

      iex> get_matching_token_for(resource_owner, application, "read invalid")
      nil

  """
  @spec get_matching_token_for(nil, OauthApplication.t(), binary()) :: OauthAccessToken.t() | nil
  def get_matching_token_for(nil, %OauthApplication{} = application, scopes) do
    %{owner_key: resource_owner_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :resource_owner)
    %{owner_key: application_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :application)

    OauthAccessToken
    |> scope_belongs_to(resource_owner_key, nil)
    |> scope_belongs_to(application_key, application)
    |> load_matching_token_for(scopes)
  end

  @spec get_matching_token_for(Schema.t(), OauthApplication.t() | nil, binary()) :: OauthAccessToken.t() | nil
  def get_matching_token_for(resource_owner, application, scopes) do
    resource_owner_clause = ExOauth2Provider.Utils.belongs_to_clause(OauthAccessToken, :resource_owner, resource_owner)
    %{owner_key: application_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :application)

    OauthAccessToken
    |> where(^resource_owner_clause)
    |> scope_belongs_to(application_key, application)
    |> load_matching_token_for(scopes)
  end

  defp load_matching_token_for(queryable, scopes) do
    queryable
    |> where([x], is_nil(x.revoked_at))
    |> order_by([x], desc: x.inserted_at)
    |> ExOauth2Provider.repo.all()
    |> Enum.filter(&is_accessible?/1)
    |> check_matching_scopes(scopes)
  end

  defp check_matching_scopes(tokens, scopes) when is_list(tokens) do
    Enum.find(tokens, nil, &check_matching_scopes(&1, scopes))
  end
  defp check_matching_scopes(nil, _), do: nil
  defp check_matching_scopes(token, scopes) do
    token_scopes   = Scopes.to_list(token.scopes)
    request_scopes = Scopes.to_list(scopes)

    case Scopes.equal?(token_scopes, request_scopes) do
      true -> token
      _    -> nil
    end
  end

  @spec get_active_tokens_for(Schema.t()) :: [OauthAccessToken.t()]
  @since "0.3.3"
  @deprecated "Use get_authorized_tokens_for/2 instead"
  def get_active_tokens_for(resource_owner) do
    get_authorized_tokens_for(resource_owner)
  end

  @doc """
  Gets all authorized access tokens for resource owner.

  ## Examples

      iex> get_authorized_tokens_for(resource_owner)
      [%OauthAccessToken{}, ...]
  """
  @spec get_authorized_tokens_for(Schema.t()) :: [OauthAccessToken.t()]
  def get_authorized_tokens_for(resource_owner) do
    resource_owner_clause = ExOauth2Provider.Utils.belongs_to_clause(OauthAccessToken, :resource_owner, resource_owner)

    OauthAccessToken
    |> where(^resource_owner_clause)
    |> where([o], is_nil(o.revoked_at))
    |> ExOauth2Provider.repo.all()
  end

  @doc """
  Creates an access token.

  ## Examples

      iex> create_token(application, %{scopes: "read write"})
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{application: application, scopes: "read write"})
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{scopes: "read write"})
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{expires_in: "invalid"})
      {:error, %Ecto.Changeset{}}
  """
  @spec create_token(Schema.t(), map()) :: {:ok, OauthAccessToken.t()} | {:error, Changeset.t()}
  def create_token(owner, attrs \\ %{})
  def create_token(%OauthApplication{} = application, attrs) do
    %OauthAccessToken{application: application}
    |> application_token_changeset(attrs)
    |> new_token_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end
  def create_token(resource_owner, %{application: %OauthApplication{} = application} = attrs) do
    %OauthAccessToken{application: application, resource_owner: resource_owner}
    |> application_owner_token_changeset(attrs)
    |> new_token_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end
  def create_token(resource_owner, attrs) do
    %OauthAccessToken{resource_owner: resource_owner}
    |> resource_owner_token_changeset(attrs)
    |> new_token_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
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

  @spec get_or_create_token(OauthApplication.t(), binary() | nil, map()) :: {:ok, OauthAccessToken.t()} | {:error, Changeset.t()}
  def get_or_create_token(%OauthApplication{} = application, scopes, attrs) do
    get_or_create_token(nil, application, scopes, attrs)
  end
  @spec get_or_create_token(Schema.t(), OauthApplication.t() | nil, binary() | nil, map()) :: {:ok, OauthAccessToken.t()} | {:error, Changeset.t()}
  def get_or_create_token(resource_owner, application, scopes, attrs) do
    attrs = Map.merge(%{scopes: scopes, application: application}, attrs)

    resource_owner
    |> get_matching_token_for(application, maybe_build_scopes(application, scopes))
    |> maybe_create_token(resource_owner, application, attrs)
  end

  defp maybe_create_token(nil, nil, application, token_params) do
    maybe_create_token(nil, application, application, token_params)
  end
  defp maybe_create_token(nil, resource_owner, _application, token_params) do
    token_params = Map.merge(%{expires_in: ExOauth2Provider.Config.access_token_expires_in()}, token_params)
    create_token(resource_owner, token_params)
  end
  defp maybe_create_token(access_token, _resource_owner, _application, _), do: {:ok, access_token}

  defp maybe_build_scopes(_application, scopes) when is_binary(scopes), do: scopes
  defp maybe_build_scopes(%{scopes: server_scopes}, nil), do: parse_default_scope_string(server_scopes)
  defp maybe_build_scopes(_application, nil), do: parse_default_scope_string(nil)

  @doc """
  Checks if an access token can be accessed.

  ## Examples

      iex> is_accessible?(token)
      true

      iex> is_accessible?(inaccessible_token)
      false

  """
  @spec is_accessible?(OauthAccessToken.t() | nil) :: boolean()
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
  @spec get_by_previous_refresh_token_for(OauthAccessToken.t()) :: OauthAccessToken.t() | nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: nil}), do: nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: ""}), do: nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: previous_refresh_token} = access_token) do
    %{owner_key: application_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :application)
    application_id = Map.get(access_token, application_key)

    %{owner_key: resource_owner_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :resource_owner)
    resource_owner_id = Map.get(access_token, resource_owner_key)

    OauthAccessToken
    |> scope_belongs_to(application_key, application_id)
    |> where([x], field(x, ^resource_owner_key) == ^resource_owner_id)
    |> where([x], x.refresh_token == ^previous_refresh_token)
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
  @spec revoke_previous_refresh_token(OauthAccessToken.t()) :: {:ok, OauthAccessToken.t()} | {:error, Changeset.t()}
  def revoke_previous_refresh_token(%OauthAccessToken{previous_refresh_token: ""} = access_token), do: access_token
  def revoke_previous_refresh_token(%OauthAccessToken{previous_refresh_token: nil} = access_token), do: access_token
  def revoke_previous_refresh_token(%OauthAccessToken{} = access_token) do
    access_token |> get_by_previous_refresh_token_for() |> revoke()

    reset_previous_refresh_token(access_token)
  end

  defp reset_previous_refresh_token(%OauthAccessToken{} = access_token) do
    access_token
    |> Ecto.Changeset.change(previous_refresh_token: "")
    |> ExOauth2Provider.repo.update()
  end

  defp application_token_changeset(token, params) do
    token
    |> cast(params, [])
    |> validate_required([:application])
    |> assoc_constraint(:application)
  end

  defp application_owner_token_changeset(token, params) do
    token
    |> application_token_changeset(params)
    |> resource_owner_token_changeset(params)
  end

  defp resource_owner_token_changeset(token, params) do
    token
    |> cast(params, [])
    |> validate_required([:resource_owner])
    |> assoc_constraint(:resource_owner)
  end

  defp new_token_changeset(changeset, params) do
    application = get_field(changeset, :application) || %OauthApplication{scopes: nil}

    changeset
    |> cast(params, [:expires_in, :scopes])
    |> put_previous_refresh_token(params[:previous_refresh_token])
    |> put_refresh_token(params[:use_refresh_token])
    |> put_scopes(application.scopes)
    |> validate_scopes(application.scopes)
    |> put_token()
  end

  defp put_token(%{} = changeset) do
    {module, method} = ExOauth2Provider.Config.access_token_generator() || {ExOauth2Provider.Utils, :generate_token}
    %{owner_key: resource_owner_key, related_key: related_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :resource_owner)

    {_, resource_owner} = fetch_field(changeset, :resource_owner)
    {_, scopes}         = fetch_field(changeset, :scopes)
    {_, application}    = fetch_field(changeset, :application)
    {_, expires_in}     = fetch_field(changeset, :expires_in)
    created_at          = NaiveDateTime.utc_now

    token = apply(module, method, [%{
      resource_owner_key => resource_owner_id(resource_owner, related_key),
      scopes: scopes,
      application: application,
      expires_in: expires_in,
      created_at: created_at}])

    changeset
    |> change(%{token: token})
    |> validate_required([:token])
    |> unique_constraint(:token)
  end

  defp resource_owner_id(nil, _key), do: nil
  defp resource_owner_id(resource_owner, related_key), do: Map.get(resource_owner, related_key)

  defp put_previous_refresh_token(%{} = changeset, %OauthAccessToken{} = refresh_token),
    do: change(changeset, %{previous_refresh_token: refresh_token.refresh_token})
  defp put_previous_refresh_token(%{} = changeset, _), do: changeset

  defp put_refresh_token(%{} = changeset, true) do
    changeset
    |> change(%{refresh_token: ExOauth2Provider.Utils.generate_token})
    |> validate_required([:refresh_token])
  end
  defp put_refresh_token(%{} = changeset, _), do: changeset
end
