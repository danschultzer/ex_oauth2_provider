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

  @doc """
  Gets a single access token.

  ## Examples

      iex> get_by_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
  @spec get_by_token(String.t) :: %OauthAccessToken{} | nil
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
  @spec get_by_refresh_token(String.t) :: %OauthAccessToken{} | nil
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
  @spec get_by_refresh_token_for(%OauthApplication{}, String.t) :: %OauthAccessToken{} | nil
  def get_by_refresh_token_for(application, refresh_token) do
    clauses = OauthAccessToken
    |> ExOauth2Provider.Utils.belongs_to_clause(:application, application)
    |> Keyword.put(:refresh_token, refresh_token)

    ExOauth2Provider.repo.get_by(OauthAccessToken, clauses)
  end

  @doc """
  Gets the most recent matching access token for a resource owner.

  ## Examples

      iex> get_matching_token_for(user, application, "read write")
      %OauthAccessToken{}

      iex> get_matching_token_for(user, application, "read invalid")
      nil

  """
  @spec get_matching_token_for(Ecto.Schema.t, %OauthApplication{}, String.t) :: %OauthAccessToken{} | nil
  def get_matching_token_for(resource_owner, application, scopes) do
    application_clause = ExOauth2Provider.Utils.belongs_to_clause(OauthAccessToken, :application, application)
    resource_owner_clause = ExOauth2Provider.Utils.belongs_to_clause(OauthAccessToken, :resource_owner, resource_owner)

    OauthAccessToken
    |> where(^application_clause)
    |> where(^resource_owner_clause)
    |> where([x], is_nil(x.revoked_at))
    |> order_by([x], desc: x.inserted_at)
    |> ExOauth2Provider.repo.all()
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

  @doc """
  Gets all active tokens for resource owner.

  ## Examples

      iex> get_active_tokens_for(resource_owner)
      [%OauthAccessToken{}, ...]
  """
  @spec get_active_tokens_for(Ecto.Schema.t) :: [%OauthAccessToken{}]
  def get_active_tokens_for(resource_owner) do
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
  @spec create_token(Ecto.Schema.t, Map.t) :: {:ok, %OauthAccessToken{}} | {:error, Ecto.Changeset.t}
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

      iex> get_or_create_token(application, attrs)
      {:ok, %OauthAccessToken{}}

      iex> get_or_create_token(user attrs)
      {:ok, %OauthAccessToken{}}

      iex> get_or_create_token(user attrs)
      {:error, %Ecto.Changeset{}}

  """
  @spec get_or_create_token(Ecto.Schema.t, Map.t) :: {:ok, %OauthAccessToken{}} | {:error, Ecto.Changeset.t}
  def get_or_create_token(owner, attrs \\ %{})
  def get_or_create_token(%OauthApplication{} = application, attrs) do
    attrs
    |> Map.put(:application, application)
    |> find_accessible_token_by_attrs()
    |> create_or_return_token(application, attrs)
  end
  def get_or_create_token(resource_owner, %{application: _} = attrs) do
    attrs
    |> Map.put(:resource_owner, resource_owner)
    |> find_accessible_token_by_attrs()
    |> create_or_return_token(resource_owner, attrs)
  end
  def get_or_create_token(resource_owner, attrs) do
    attrs
    |> Map.put(:resource_owner, resource_owner)
    |> find_accessible_token_by_attrs()
    |> create_or_return_token(resource_owner, attrs)
  end

  defp find_accessible_token_by_attrs(attrs) do
    attrs
    |> tranform_assocations_in_attrs()
    |> Map.delete(:use_refresh_token)
    |> build_access_token_by_attrs_query()
    |> ExOauth2Provider.repo.one()
    |> filter_accessible()
  end

  defp tranform_assocations_in_attrs(attrs) do
    attrs
    |> transform_resource_owner_assocation_in_attrs()
    |> transform_application_assocation_in_attrs()
  end

  defp transform_resource_owner_assocation_in_attrs(%{resource_owner: resource_owner} = attrs) do
    resource_owner_clause = OauthAccessToken
    |> ExOauth2Provider.Utils.belongs_to_clause(:resource_owner, resource_owner)
    |> Enum.into(%{})

    attrs
    |> Map.merge(resource_owner_clause)
    |> Map.delete(:resource_owner)
  end
  defp transform_resource_owner_assocation_in_attrs(attrs), do: attrs

  defp transform_application_assocation_in_attrs(%{application: application} = attrs) do
    application_clause = OauthAccessToken
    |> ExOauth2Provider.Utils.belongs_to_clause(:application, application)
    |> Enum.into(%{})

    attrs
    |> Map.merge(application_clause)
    |> Map.delete(:application)
  end
  defp transform_application_assocation_in_attrs(attrs), do: attrs

  defp build_access_token_by_attrs_query(attrs) do
    %{owner_key: application_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :application)
    %{owner_key: resource_owner_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :resource_owner)

    attrs
    |> Enum.reduce(OauthAccessToken, fn({k, v}, query) ->
         case Enum.member?([application_key, resource_owner_key, :scopes], k) and is_nil(v) do
           true  -> where(query, [o], is_nil(field(o, ^k)))
           false -> where(query, [o], field(o, ^k) == ^v)
         end
       end)
    |> limit(1)
  end

  defp filter_accessible(access_token) do
    case is_accessible?(access_token) do
      true  -> access_token
      false -> nil
    end
  end

  defp create_or_return_token(nil, owner, attrs), do: create_token(owner, attrs)
  defp create_or_return_token(access_token, _, _), do: {:ok, access_token}

  @doc """
  Checks if an access token can be accessed.

  ## Examples

      iex> is_accessible?(token)
      true

      iex> is_accessible?(inaccessible_token)
      false

  """
  @spec is_accessible?(%OauthAccessToken{}) :: boolean
  @spec is_accessible?(nil) :: false
  def is_accessible?(%OauthAccessToken{} = token) do
    !is_expired?(token) and !is_revoked?(token)
  end
  def is_accessible?(nil), do: false

  @doc """
  Gets an old access token by previous refresh token.

  ## Examples

      iex> get_by_previous_refresh_token_for(new_access_token)
      %OauthAccessToken{}

      iex> get_by_previous_refresh_token_for(new_access_token)
      nil
  """
  @spec get_by_previous_refresh_token_for(%OauthAccessToken{}) :: %OauthAccessToken{} | nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: nil}), do: nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: ""}), do: nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: previous_refresh_token} = access_token) do
    %{owner_key: application_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :application)
    application_id = Map.get(access_token, application_key)

    %{owner_key: resource_owner_key} = ExOauth2Provider.Utils.schema_association(OauthAccessToken, :resource_owner)
    resource_owner_id = Map.get(access_token, resource_owner_key)

    OauthAccessToken
    |> scope_application(application_key, application_id)
    |> where([x], field(x, ^resource_owner_key) == ^resource_owner_id)
    |> where([x], x.refresh_token == ^previous_refresh_token)
    |> limit(1)
    |> ExOauth2Provider.repo.one()
  end

  defp scope_application(queryable, application_key, nil) do
    where(queryable, [x], is_nil(field(x, ^application_key)))
  end
  defp scope_application(queryable, application_key, application_id) do
    where(queryable, [x], field(x, ^application_key) == ^application_id)
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
  @spec revoke_previous_refresh_token(%OauthAccessToken{}) :: {:ok, %OauthAccessToken{}} | {:error, Ecto.Changeset.t}
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
