defmodule Dummy.User do
  @moduledoc false

  use Dummy.Schema
  alias Ecto.Changeset

  schema "users" do
    field :email, :string
    has_many :tokens, ExOauth2Provider.OauthAccessTokens.OauthAccessToken, foreign_key: :resource_owner_id

    timestamps()
  end

  def changeset(struct, params \\ %{}) do
    Changeset.cast(struct, params, [:email])
  end
end
