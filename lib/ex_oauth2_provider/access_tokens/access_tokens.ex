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

  defdelegate revoke!(data, config \\ []), to: Revocable
  defdelegate revoke(data, config \\ []), to: Revocable
  defdelegate is_expired?(token), to: Expirable
  defdelegate is_revoked?(token), to: Revocable

  @doc """
  Gets a single access token.

  ## Examples

      iex> get_by_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d", otp_app: :my_app)
      %OauthAccessToken{}

      iex> get_by_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc", otp_app: :my_app)
      nil

  """
  @spec get_by_token(binary(), keyword()) :: AccessToken.t() | nil
  def get_by_token(token, config \\ []) do
    config
    |> Config.access_token()
    |> Config.repo(config).get_by(token: token)
  end

  @doc """
  Gets an access token by the refresh token.

  ## Examples

      iex> get_by_refresh_token("c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d", otp_app: :my_app)
      %OauthAccessToken{}

      iex> get_by_refresh_token("75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc", otp_app: :my_app)
      nil
  """
  @spec get_by_refresh_token(binary(), keyword()) :: AccessToken.t() | nil
  def get_by_refresh_token(refresh_token, config \\ []) do
    config
    |> Config.access_token()
    |> Config.repo(config).get_by(refresh_token: refresh_token)
  end

  @doc """
  Gets an access token by the refresh token belonging to an application.

  ## Examples

      iex> get_by_refresh_token_for(application, "c341a5c7b331ef076eb4954668d54f590e0009e06b81b100191aa22c93044f3d", otp_app: :my_app)
      %OauthAccessToken{}

      iex> get_by_refresh_token_for(application, "75d72f326a69444a9287ea264617058dbbfe754d7071b8eef8294cbf4e7e0fdc", otp_app: :my_app)
      nil
  """
  @spec get_by_refresh_token_for(Application.t(), binary(), keyword()) :: AccessToken.t() | nil
  def get_by_refresh_token_for(application, refresh_token, config \\ []) do
    config
    |> Config.access_token()
    |> Config.repo(config).get_by(application_id: application.id, refresh_token: refresh_token)
  end

  @doc """
  Gets the most recent, acccessible, matching access token for a resource owner.

  ## Examples

      iex> get_token_for(resource_owner, application, "read write", otp_app: :my_app)
      %OauthAccessToken{}

      iex> get_token_for(resource_owner, application, "read invalid", otp_app: :my_app)
      nil
  """
  @spec get_token_for(Schema.t(), Application.t(), binary(), keyword()) :: AccessToken.t() | nil
  def get_token_for(resource_owner, application, scopes, config \\ []) do
    config
    |> Config.access_token()
    |> scope_belongs_to(:resource_owner_id, resource_owner)
    |> scope_belongs_to(:application_id, application)
    |> load_matching_token_for(application, scopes, config)
  end

  @doc """
  Gets the most recent, acccessible, matching access token for an application.

  ## Examples

      iex> get_application_token_for(application, "read write", otp_app: :my_app)
      %OauthAccessToken{}

      iex> get_application_token_for(application, "read invalid", otp_app: :my_app)
      nil
  """
  @spec get_application_token_for(Application.t(), binary(), keyword()) :: AccessToken.t() | nil
  def get_application_token_for(application, scopes, config \\ []) do
    config
    |> Config.access_token()
    |> scope_belongs_to(:resource_owner_id, nil)
    |> scope_belongs_to(:application_id, application)
    |> load_matching_token_for(application, scopes, config)
  end

  defp load_matching_token_for(queryable, application, scopes, config) do
    now =
      config
      |> Config.access_token()
      |> SchemaHelpers.__timestamp_for__(:inserted_at)

    scopes = maybe_build_scopes(application, scopes, config)

    queryable
    |> where([a], is_nil(a.revoked_at))
    |> where(
      [a],
      is_nil(a.expires_in) or datetime_add(a.inserted_at, a.expires_in, "second") > ^now
    )
    |> order_by([a], desc: a.inserted_at, desc: :id)
    |> Config.repo(config).all()
    |> Enum.filter(&is_accessible?/1)
    |> check_matching_scopes(scopes)
  end

  defp maybe_build_scopes(_application, scopes, _config) when is_binary(scopes), do: scopes

  defp maybe_build_scopes(%{scopes: server_scopes}, nil, config),
    do: Scopes.parse_default_scope_string(server_scopes, config)

  defp maybe_build_scopes(_application, nil, config),
    do: Scopes.parse_default_scope_string(nil, config)

  defp check_matching_scopes(tokens, scopes) when is_list(tokens) do
    Enum.find(tokens, nil, &check_matching_scopes(&1, scopes))
  end

  defp check_matching_scopes(nil, _), do: nil

  defp check_matching_scopes(token, scopes) do
    token_scopes = ScopesUtils.to_list(token.scopes)
    request_scopes = ScopesUtils.to_list(scopes)

    case ScopesUtils.equal?(token_scopes, request_scopes) do
      true -> token
      _ -> nil
    end
  end

  @doc """
  Gets all authorized access tokens for resource owner.

  ## Examples

      iex> get_authorized_tokens_for(resource_owner, otp_app: :my_app)
      [%OauthAccessToken{}, ...]
  """
  @spec get_authorized_tokens_for(Schema.t(), keyword()) :: [AccessToken.t()]
  def get_authorized_tokens_for(resource_owner, config \\ []) do
    config
    |> Config.access_token()
    |> where([a], a.resource_owner_id == ^resource_owner.id)
    |> where([a], is_nil(a.revoked_at))
    |> Config.repo(config).all()
  end

  @doc """
  Creates an access token.

  ## Examples

      iex> create_token(resource_owner, %{application: application, scopes: "read write"}, otp_app: :my_app)
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{scopes: "read write"}, otp_app: :my_app)
      {:ok, %OauthAccessToken{}}

      iex> create_token(resource_owner, %{expires_in: "invalid"}, otp_app: :my_app)
      {:error, %Ecto.Changeset{}}
  """
  @spec create_token(Schema.t(), map(), keyword()) ::
          {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def create_token(resource_owner, attrs \\ %{}, config \\ []) do
    config
    |> Config.access_token()
    |> struct(resource_owner: resource_owner)
    |> put_application(attrs)
    |> do_create_token(attrs, config)
  end

  defp put_application(access_token, attrs) do
    case Map.get(attrs, :application) do
      nil -> access_token
      application -> %{access_token | application: application}
    end
  end

  defp do_create_token(access_token, attrs, config) do
    attrs = Map.merge(%{expires_in: Config.access_token_expires_in(config)}, attrs)

    access_token
    |> AccessToken.changeset(attrs, config)
    |> Config.repo(config).insert()
  end

  @doc """
  Creates an application access token.

  ## Examples

      iex> create_application_token(application, %{scopes: "read write"}, otp_app: :my_app)
      {:ok, %OauthAccessToken{}}
  """
  @spec create_application_token(Schema.t() | nil, map(), keyword()) ::
          {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def create_application_token(application, attrs \\ %{}, config \\ []) do
    config
    |> Config.access_token()
    |> struct(application: application)
    |> do_create_token(attrs, config)
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

      iex> get_by_previous_refresh_token_for(new_access_token, otp_app: :my_app)
      %OauthAccessToken{}

      iex> get_by_previous_refresh_token_for(new_access_token, otp_app: :my_app)
      nil
  """
  @spec get_by_previous_refresh_token_for(AccessToken.t(), keyword()) :: AccessToken.t() | nil
  def get_by_previous_refresh_token_for(%{previous_refresh_token: nil}, _config), do: nil
  def get_by_previous_refresh_token_for(%{previous_refresh_token: ""}, _config), do: nil

  def get_by_previous_refresh_token_for(
        %{
          previous_refresh_token: previous_refresh_token,
          resource_owner_id: resource_owner_id,
          application_id: application_id
        },
        config
      ) do
    config
    |> Config.access_token()
    |> scope_belongs_to(:application_id, application_id)
    |> where([a], a.resource_owner_id == ^resource_owner_id)
    |> where([a], a.refresh_token == ^previous_refresh_token)
    |> limit(1)
    |> Config.repo(config).one()
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

      iex> revoke_previous_refresh_token(data, otp_app: :my_app)
      {:ok, %OauthAccessToken{}}

      iex> revoke_previous_refresh_token(invalid_data, otp_app: :my_app)
      {:error, %Ecto.Changeset{}}
  """
  @spec revoke_previous_refresh_token(AccessToken.t()) ::
          {:ok, AccessToken.t()} | {:error, Changeset.t()}
  def revoke_previous_refresh_token(access_token, config \\ [])

  def revoke_previous_refresh_token(%{previous_refresh_token: ""} = access_token, _config),
    do: {:ok, access_token}

  def revoke_previous_refresh_token(%{previous_refresh_token: nil} = access_token, _config),
    do: {:ok, access_token}

  def revoke_previous_refresh_token(access_token, config) do
    access_token
    |> get_by_previous_refresh_token_for(config)
    |> revoke(config)

    reset_previous_refresh_token(access_token, config)
  end

  defp reset_previous_refresh_token(access_token, config) do
    access_token
    |> Changeset.change(previous_refresh_token: "")
    |> Config.repo(config).update()
  end
end
