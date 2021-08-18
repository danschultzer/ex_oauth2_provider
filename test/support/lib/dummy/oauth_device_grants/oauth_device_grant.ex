defmodule Dummy.OauthDeviceGrants.OauthDeviceGrant do
  @moduledoc false

  use Ecto.Schema
  use ExOauth2Provider.DeviceGrants.DeviceGrant, otp_app: :ex_oauth2_provider

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "oauth_device_grants" do
    device_grant_fields()
    timestamps()
  end
end
