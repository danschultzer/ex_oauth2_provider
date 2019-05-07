defmodule Dummy.OauthApplications.OauthApplication do
  use Ecto.Schema
  use ExOauth2Provider.Applications.Application

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "oauth_applications" do
    application_fields()
    timestamps()
  end
end
