defmodule Dummy.Users.User do
  @moduledoc false
  use Ecto.Schema

  if System.get_env("UUID") do
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id
  end

  schema "users" do
    field :email, :string
    has_many :tokens, Dummy.OauthAccessTokens.OauthAccessToken, foreign_key: :resource_owner_id

    timestamps()
  end
end
