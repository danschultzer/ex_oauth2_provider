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

  @doc """
  Gets a single access token.

  ## Examples

      iex> get_by_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d")
      %OauthAccessToken{}

      iex> get_by_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc")
      nil

  """
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
  def get_by_refresh_token_for(%OauthApplication{} = application, refresh_token) do
    ExOauth2Provider.repo.get_by(OauthAccessToken, application_id: application.id, refresh_token: refresh_token)
  end

  @doc """
  Gets the most recent matching access token for a resource owner.

  ## Examples

      iex> get_matching_token_for(user, application, "read write")
      %OauthAccessToken{}

      iex> get_matching_token_for(user, application, "read invalid")
      nil

  """
  def get_matching_token_for(%{id: resource_owner_id}, %OauthApplication{id: application_id}, scopes) do
    OauthAccessToken
    |> where([x], x.application_id == ^application_id)
    |> where([x], x.resource_owner_id == ^resource_owner_id)
    |> where([x], is_nil(x.revoked_at))
    |> order_by([x], desc: x.inserted_at)
    |> limit(1)
    |> ExOauth2Provider.repo.one
    |> check_matching_scopes(scopes)
  end

  defp check_matching_scopes(nil, _), do: nil
  defp check_matching_scopes(token, scopes) do
    token_scopes   = token.scopes |> ExOauth2Provider.Scopes.to_list
    request_scopes = scopes |> ExOauth2Provider.Scopes.to_list

    case ExOauth2Provider.Scopes.equal?(token_scopes, request_scopes) do
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
  def get_active_tokens_for(%{id: resource_owner_id}) do
    ExOauth2Provider.repo.all(from o in OauthAccessToken,
                              where: o.resource_owner_id == ^resource_owner_id and
                                     is_nil(o.revoked_at))
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
  def create_token(owner, attrs \\ %{})
  def create_token(%OauthApplication{} = application, attrs) do
    %OauthAccessToken{application: application}
    |> application_token_changeset(attrs)
    |> new_token_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end
  def create_token(%{id: _} = resource_owner, %{application: application} = attrs) do
    %OauthAccessToken{application: application, resource_owner: resource_owner}
    |> application_owner_token_changeset(attrs)
    |> new_token_changeset(attrs)
    |> ExOauth2Provider.repo.insert()
  end
  def create_token(%{id: _} = resource_owner, attrs) do
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
  def get_or_create_token(owner, attrs \\ %{})
  def get_or_create_token(%OauthApplication{id: _} = application, attrs) do
    attrs
    |> Map.merge(%{application: application})
    |> find_accessible_token_by_attrs
    |> create_or_return_token(application, attrs)
  end
  def get_or_create_token(%{id: _} = resource_owner, %{application: _} = attrs) do
    attrs
    |> Map.merge(%{resource_owner: resource_owner})
    |> find_accessible_token_by_attrs
    |> create_or_return_token(resource_owner, attrs)
  end
  def get_or_create_token(%{id: _} = resource_owner, attrs) do
    attrs
    |> Map.merge(%{resource_owner: resource_owner})
    |> find_accessible_token_by_attrs
    |> create_or_return_token(resource_owner, attrs)
  end

  defp find_accessible_token_by_attrs(attrs) do
    attrs
    |> tranform_assocations_in_attrs
    |> Map.delete(:use_refresh_token)
    |> build_access_token_by_attrs_query
    |> ExOauth2Provider.repo.one
    |> filter_accessible
  end

  defp tranform_assocations_in_attrs(attrs) do
    attrs
    |> transform_resource_owner_assocation_in_attrs
    |> transform_application_assocation_in_attrs
  end

  defp transform_resource_owner_assocation_in_attrs(%{resource_owner: resource_owner} = attrs) do
    attrs
    |> Map.merge(%{resource_owner_id: resource_owner.id})
    |> Map.delete(:resource_owner)
  end
  defp transform_resource_owner_assocation_in_attrs(attrs), do: attrs

  defp transform_application_assocation_in_attrs(%{application: application} = attrs) do
    attrs
    |> Map.merge(%{application_id: application.id})
    |> Map.delete(:application)
  end
  defp transform_application_assocation_in_attrs(attrs), do: attrs

  defp build_access_token_by_attrs_query(attrs) do
    attrs
    |> Enum.reduce(OauthAccessToken, fn({k, v}, query) ->
         case Enum.member?([:application_id, :resource_owner_id, :scopes], k) and is_nil(v) do
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
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: nil}), do: nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{previous_refresh_token: ""}), do: nil
  def get_by_previous_refresh_token_for(%OauthAccessToken{application_id: application_id, resource_owner_id: resource_owner_id, previous_refresh_token: previous_refresh_token}) do
    application_id
    |> is_nil
    |> (case do
          true  -> OauthAccessToken |> where([x], is_nil(x.application_id))
          false -> OauthAccessToken |> where([x], x.application_id == ^application_id)
        end)
    |> where([x], x.resource_owner_id == ^resource_owner_id)
    |> where([x], x.refresh_token == ^previous_refresh_token)
    |> limit(1)
    |> ExOauth2Provider.repo.one
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
  def revoke_previous_refresh_token(%OauthAccessToken{previous_refresh_token: ""} = access_token), do: access_token
  def revoke_previous_refresh_token(%OauthAccessToken{previous_refresh_token: nil} = access_token), do: access_token
  def revoke_previous_refresh_token(%OauthAccessToken{} = access_token) do
    access_token
    |> get_by_previous_refresh_token_for
    |> revoke

    access_token
    |> reset_previous_refresh_token
  end

  defp reset_previous_refresh_token(%OauthAccessToken{} = access_token) do
    changeset = Ecto.Changeset.change access_token, previous_refresh_token: ""
    ExOauth2Provider.repo.update(changeset)
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
    application = get_field(changeset, :application) || %{scopes: nil}

    changeset
    |> cast(params, [:expires_in, :scopes])
    |> put_previous_refresh_token(params[:previous_refresh_token])
    |> put_refresh_token(params[:use_refresh_token])
    |> put_scopes(application.scopes)
    |> validate_scopes(application.scopes)
    |> put_token
  end

  defp put_token(%{} = changeset) do
    {module, method} = ExOauth2Provider.Config.access_token_generator() || {ExOauth2Provider.Utils, :generate_token}

    {_, resource_owner} = fetch_field(changeset, :resource_owner)
    resource_owner_id   = if is_nil(resource_owner), do: nil, else: resource_owner.id
    {_, scopes}         = fetch_field(changeset, :scopes)
    {_, application}    = fetch_field(changeset, :application)
    {_, expires_in}     = fetch_field(changeset, :expires_in)
    created_at          = NaiveDateTime.utc_now

    token = apply(module, method, [%{
      resource_owner_id: resource_owner_id,
      scopes: scopes,
      application: application,
      expires_in: expires_in,
      created_at: created_at}])

    changeset
    |> change(%{token: token})
    |> validate_required([:token])
    |> unique_constraint(:token)
  end

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
