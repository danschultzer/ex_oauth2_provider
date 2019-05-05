defmodule Mix.Tasks.ExOauth2Provider.Gen.Migration do
  @shortdoc "Generates ex_oauth2_provider migration file"

  @moduledoc """
  Generates ex_oauth2_provider migration files.

      mix ex_oauth2_provider.gen.migrations -r MyApp.Repo

      mix ex_oauth2_provider.gen.migrations -r MyApp.Repo --namespace oauth2

  This generator will add the oauth2 migration file in `priv/repo/migrations`.

  The repository must be set under `:ecto_repos` in the current app
  configuration or given via the `-r` option.

  By default, the migration will be generated to the
  "priv/YOUR_REPO/migrations" directory of the current application but it
  can be configured to be any subdirectory of `priv` by specifying the
  `:priv` key under the repository configuration.

  ## Arguments

    * `-r`, `--repo` - the repo module
    * `--binary-id` - use binary id for primary key
    * `--namespace` - schema namespace to use, defaults to `oauth`
  """
  use Mix.Task

  alias Mix.{Ecto, ExOauth2Provider, ExOauth2Provider.Migration}

  @switches [binary_id: :boolean]
  @default_opts [binary_id: false]
  @mix_task "ex_oauth2_provider.gen.migrations"
  @migration_content """
  defmodule <%= inspect schema.repo %>.Migrations.<%= schema.migration_name %> do
    use Ecto.Migration

    def change do
      create table(:<%= schema.namespace %>_applications<%= if schema.binary_id do %>, primary_key: false<% end %>) do
  <%= if schema.binary_id do %>      add :id, :binary_id, primary_key: true
  <% end %>      add :owner_id, references(:users<%= if schema.binary_id do %>, type: :binary_id<% end %>)
        add :name, :string,  null: false
        add :uid, :string, null: false
        add :secret, :string, null: false
        add :redirect_uri, :string, null: false
        add :scopes,  :string, null: false, default: ""

        timestamps()
      end

      create unique_index(:<%= schema.namespace %>_applications, [:uid])
      create index(:<%= schema.namespace %>_applications, [:owner_id])

      create table(:<%= schema.namespace %>_access_grants<%= if schema.binary_id do %>, primary_key: false<% end %>) do
        <%= if schema.binary_id do %>      add :id, :binary_id, primary_key: true
  <% end %>      add :resource_owner_id, references(:users<%= if schema.binary_id do %>, type: :binary_id<% end %>)
        add :application_id, references(:<%= schema.namespace %>_applications<%= if schema.binary_id do %>, type: :binary_id<% end %>)
        add :token, :string, null: false
        add :expires_in, :integer, null: false
        add :redirect_uri, :string, null: false
        add :revoked_at, :naive_datetime
        add :scopes, :string

        timestamps(updated_at: false)
      end

      create unique_index(:<%= schema.namespace %>_access_grants, [:token])

      create table(:<%= schema.namespace %>_access_tokens<%= if schema.binary_id do %>, primary_key: false<% end %>) do
        <%= if schema.binary_id do %>add :id, :binary_id, primary_key: true
  <% end %>      add :application_id, references(:<%= schema.namespace %>_applications<%= if schema.binary_id do %>, type: :binary_id <% end %>)
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

      create unique_index(:<%= schema.namespace %>_access_tokens, [:token])
      create index(:<%= schema.namespace %>_access_tokens, [:resource_owner_id])
      create unique_index(:<%= schema.namespace %>_access_tokens, [:refresh_token])
    end
  end
  """

  @impl true
  def run(args) do
    ExOauth2Provider.no_umbrella!(@mix_task)

    args
    |> ExOauth2Provider.parse_options(@switches, @default_opts)
    |> parse()
    |> create_migration_files(args)
  end

  defp parse({config, parsed, _invalid}) do
    namespace = case parsed do
      [namespace] -> namespace
      _           -> "oauth"
    end

    Map.put(config, :schema_namespace, namespace)
  end

  defp create_migration_files(config, args) do
    args
    |> Ecto.parse_repo()
    |> Enum.map(&Ecto.ensure_repo(&1, args))
    |> Enum.map(&Map.put(config, :repo, &1))
    |> Enum.each(&create_migration_files/1)
  end

  defp create_migration_files(%{repo: repo, binary_id: binary_id, schema_namespace: schema_namespace}) do
    repo             = repo || Module.concat([ExOauth2Provider.app_base(ExOauth2Provider.otp_app()), "Repo"])
    migration_name   = "Create#{Macro.camelize(schema_namespace)}Tables"
    content          = EEx.eval_string(@migration_content, schema: %{namespace: schema_namespace, migration_name: migration_name, repo: repo, binary_id: binary_id})

    Migration.create_migration_file(repo, migration_name, content)
  end
end
