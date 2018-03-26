defmodule <%= inspect mod %> do
  use Ecto.Migration

  def change do
    create table(:oauth_applications<%= if uuid[:oauth_applications], do: ", primary_key: false" %>) do<%= if uuid[:oauth_applications] do %>
      add :id,                :uuid,    primary_key: true<% end %><%= if uuid[:resource_owners] do %>
      add :owner_id,          :uuid,    null: false<% else %>
      add :owner_id,          :integer, null: false<% end %>
      add :name,              :string,  null: false
      add :uid,               :string,  null: false
      add :secret,            :string,  null: false
      add :redirect_uri,      :string,  null: false
      add :scopes,            :string,  null: false, default: ""

      timestamps()
    end

    create unique_index(:oauth_applications, [:uid])
    create index(:oauth_applications, [:owner_id])

    create table(:oauth_access_grants<%= if uuid[:oauth_access_grants], do: ", primary_key: false" %>) do<%= if uuid[:oauth_access_grants] do %>
      add :id,                     :uuid,           primary_key: true<% end %><%= if uuid[:resource_owners] do %>
      add :resource_owner_id,      :uuid,           null: false<% else %>
      add :resource_owner_id,      :integer,        null: false<% end %>
      add :application_id,         references(:oauth_applications<%= if uuid[:oauth_applications], do: ", type: :uuid" %>)
      add :token,                  :string,         null: false
      add :expires_in,             :integer,        null: false
      add :redirect_uri,           :string,         null: false
      add :revoked_at,             :naive_datetime
      add :scopes,                 :string

      timestamps(updated_at: false)
    end

    create unique_index(:oauth_access_grants, [:token])

    create table(:oauth_access_tokens<%= if uuid[:oauth_access_tokens], do: ", primary_key: false" %>) do<%= if uuid[:oauth_access_tokens] do %>
      add :id,                     :uuid, primary_key: true<% end %>
      add :application_id,         references(:oauth_applications<%= if uuid[:oauth_applications], do: ", type: :uuid" %>)<%= if uuid[:resource_owners] do %>
      add :resource_owner_id,      :uuid<% else %>
      add :resource_owner_id,      :integer<% end %>

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
      add :previous_refresh_token, :string, null: false, default: ""

      timestamps()
    end

    create unique_index(:oauth_access_tokens, [:token])
    create index(:oauth_access_tokens, [:resource_owner_id])
    create unique_index(:oauth_access_tokens, [:refresh_token])
  end
end
