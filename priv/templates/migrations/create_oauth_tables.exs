defmodule <%= inspect mod %> do
  use Ecto.Migration

  def change do
    create table(:oauth_applications) do
      add :resource_owner_id, :integer, null: false
      add :name,              :string,  null: false
      add :uid,               :string,  null: false
      add :secret,            :string,  null: false
      add :redirect_uri,      :string,  null: false
      add :scopes,            :string,  null: false, default: ""

      timestamps()
    end

    create unique_index(:oauth_applications, [:uid])
    create index(:oauth_applications, [:resource_owner_id])

    create table(:oauth_access_tokens) do
      add :application_id,         references(:oauth_applications)
      add :resource_owner_id,      :integer, null: false

      # If you use a custom token generator you may need to change this column
      # from string to text, so that it accepts tokens larger than 255
      # characters.
      #
      # add : token,                  :text, null: false
      add :token,                  :string, null: false
      add :refresh_token,          :string
      add :expires_in,             :integer
      add :revoked_at,             :naive_datetime
      add :scopes,                 :string

      # If there is a previous_refresh_token column,
      # refresh tokens will be revoked after a related access token is used.
      # If there is no previous_refresh_token column,
      # previous tokens are revoked as soon as a new access token is created.
      # Comment out this line if you'd rather have refresh tokens
      # instantly revoked.
      add :previous_refresh_token, :string, null: false, default: ""

      timestamps()
    end

    create unique_index(:oauth_access_tokens, [:token])
    create index(:oauth_access_tokens, [:resource_owner_id])
    create unique_index(:oauth_access_tokens, [:refresh_token])
  end
end
