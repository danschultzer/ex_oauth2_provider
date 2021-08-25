defmodule ExOauth2Provider.DeviceGrants do
  @moduledoc """
  The boundary for the OauthDeviceGrants system.
  """

  import Ecto.Query
  alias ExOauth2Provider.Mixin.{Expirable}

  alias ExOauth2Provider.{
    Applications.Application,
    DeviceGrants.DeviceGrant,
    Config
  }

  defdelegate is_expired?(device_grant), to: Expirable

  def authorize(device_grant, resource_owner, config) do
    params = %{resource_owner_id: resource_owner.id, user_code: nil}

    device_grant
    |> DeviceGrant.changeset(params, config)
    |> get_repo(config).update()
  end

  @doc """
  Creates a device grant.

  ## Examples

      iex> create_grant(application, attrs)
      {:ok, %OauthDeviceGrant{}}

      iex> create_grant(application, attrs)
      {:error, %Ecto.Changeset{}}

  """
  @spec create_grant(Application.t(), map(), keyword()) ::
          {:ok, DeviceGrant.t()} | {:error, term()}
  def create_grant(application, attrs, config \\ []) do
    {schema, repo} = schema_and_repo_from_config(config)

    schema
    |> struct(application: application)
    |> DeviceGrant.changeset(attrs, config)
    |> repo.insert()
  end

  def delete_expired(config) do
    {schema, repo} = schema_and_repo_from_config(config)
    lifespan = Config.authorization_code_expires_in(config)

    from(
      d in schema,
      where: d.inserted_at <= ago(^lifespan, "second")
    )
    |> repo.delete_all()
  end

  def delete!(grant, config) do
    get_repo(config).delete!(grant)
  end

  @doc """
  Gets a single device grant registered with an application.

  ## Examples

      iex> find_by_application_and_device_code(application, "jE9dk", otp_app: :my_app)
      %OauthDeviceGrant{}

      iex> find_by_application_and_device_code(application, "jE9dk", otp_app: :my_app)
      ** nil

  """
  @spec find_by_application_and_device_code(Application.t(), binary(), keyword()) ::
          DeviceGrant.t() | nil
  def find_by_application_and_device_code(application, device_code, config \\ []) do
    {schema, repo} = schema_and_repo_from_config(config)
    repo.get_by(schema, application_id: application.id, device_code: device_code)
  end

  def find_by_user_code(nil, _config), do: nil

  # DeviceGrant | nil
  def find_by_user_code(user_code, config) do
    config
    |> schema_and_repo_from_config()
    |> fetch_grant_with_user_code(user_code)
  end

  def update_last_polled_at!(grant, config) do
    grant
    |> DeviceGrant.changeset(%{last_polled_at: DateTime.utc_now()}, config)
    |> get_repo(config).update!()
  end

  defp fetch_grant_with_user_code({schema, repo}, user_code) do
    # from(d in schema, preload: [:application], where: d.user_code == ^user_code)
    schema
    |> repo.get_by(user_code: user_code)
    |> repo.preload(:application)
  end

  defp get_repo(config), do: Config.repo(config)

  defp schema_and_repo_from_config(config) do
    {
      Config.device_grant(config),
      Config.repo(config)
    }
  end
end
