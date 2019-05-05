defmodule <%= inspect schema.repo %>.Migrations.<%= schema.migration_name %> do
  use Ecto.Migration

  def change do
    create table(:<%= schema_namespace %>_applications<%= if schema.binary_id do %>, primary_key: false<% end %>) do
<%= if schema.binary_id do %>      add :id, :binary_id, primary_key: true
<% end %>      add :owner_id, references(:users<%= if schema.binary_id do %>, type: :binary_id<% end %>)
      add :name, :string,  null: false
      add :uid, :string, null: false
      add :secret, :string, null: false
      add :redirect_uri, :string, null: false
      add :scopes,  :string, null: false, default: ""

      timestamps()
    end

    create unique_index(:<%= schema_namespace %>_applications, [:uid])
    create index(:<%= schema_namespace %>_applications, [:owner_id])

    create table(:<%= schema_namespace %>_access_grants<%= if schema.binary_id do %>, primary_key: false<% end %>) do
      <%= if schema.binary_id do %>      add :id, :binary_id, primary_key: true
<% end %>      add :resource_owner_id, references(:users<%= if schema.binary_id do %>, type: :binary_id<% end %>)
      add :application_id, references(:<%= schema_namespace %>_applications<%= if schema.binary_id do %>, type: :binary_id<% end %>)
      add :token, :string, null: false
      add :expires_in, :integer, null: false
      add :redirect_uri, :string, null: false
      add :revoked_at, :naive_datetime
      add :scopes, :string

      timestamps(updated_at: false)
    end

    create unique_index(:<%= schema_namespace %>_access_grants, [:token])

    create table(:<%= schema_namespace %>_access_tokens<%= if schema.binary_id do %>, primary_key: false<% end %>) do
      <%= if schema.binary_id do %>add :id, :binary_id, primary_key: true
<% end %>      add :application_id, references(:<%= schema_namespace %>_applications<%= if schema.binary_id do %>, type: :binary_id <% end %>)
      add :resource_owner_id, references(:users<%= if schema.binary_id do %>, type: :binary_id <% end %>)

      # If you use a custom token generator you may need to change this column
      # from string to text, so that it accepts tokens larger than 255
      # characters.
      #
      # add : token, :text, null: false
      add :token, :string, null: false
      add :refresh_token, :string
      add :expires_in, :integer
      add :revoked_at, :naive_datetime
      add :scopes, :string
      add :previous_refresh_token, :string, null: false, default: ""

      timestamps()
    end

    create unique_index(:<%= schema_namespace %>_access_tokens, [:token])
    create index(:<%= schema_namespace %>_access_tokens, [:resource_owner_id])
    create unique_index(:<%= schema_namespace %>_access_tokens, [:refresh_token])
  end
end
