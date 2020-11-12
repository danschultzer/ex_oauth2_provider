defmodule Mix.ExOauth2Provider.Schema do
  @moduledoc false

  alias Mix.Generator
  alias ExOauth2Provider.Config

  @template """
  defmodule <%= inspect schema.module %> do
    use Ecto.Schema
    use <%= inspect schema.macro %>, otp_app: :<%= otp_app %>
  <%= if schema.binary_id do %>
    @primary_key {:id, :binary_id, autogenerate: true}
    @foreign_key_type :binary_id<% end %>
    schema <%= inspect schema.table_name %> do
      <%= schema.table %>_fields()

      timestamps()
    end<%= if schema.changeset do %>

    @impl ExOauth2Provider.Changeset
    def allowed_fields do
      <%= schema.table %>_allowed_fields()
    end

    @impl ExOauth2Provider.Changeset
    def required_fields do
      <%= schema.table %>_required_fields()
    end

    @impl ExOauth2Provider.Changeset
    def request_fields do
      <%= schema.table %>_request_fields()
    end<% end %>
  end
  """

  alias ExOauth2Provider.{AccessGrants.AccessGrant, AccessTokens.AccessToken, Applications.Application}

  @schemas [
    {"application", Application, false},
    {"access_grant", AccessGrant, true},
    {"access_token", AccessToken, true}
  ]

  @spec create_schema_files(atom(), binary(), keyword()) :: any()
  def create_schema_files(context_app, namespace, opts) do
    for {table, schema, changeset} <- @schemas do
      app_base     = Config.app_base(context_app)
      table_name   = "#{namespace}_#{table}s"
      context      = Macro.camelize(table_name)
      module       = Macro.camelize("#{namespace}_#{table}")
      file         = "#{Macro.underscore(module)}.ex"
      module       = Module.concat([app_base, context, module])
      binary_id    = Keyword.get(opts, :binary_id, false)
      macro        = schema
      content      = EEx.eval_string(@template, schema: %{module: module, table: table, table_name: table_name, binary_id: binary_id, macro: macro, changeset: changeset}, otp_app: context_app)
      dir          = "lib/#{context_app}/#{Macro.underscore(context)}/"

      File.mkdir_p!(dir)

      dir
      |> Path.join(file)
      |> Generator.create_file(content)
    end
  end
end
