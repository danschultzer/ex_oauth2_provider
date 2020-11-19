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
    schema <%= inspect schema.table %> do
      <%= schema.macro_fields %>()

      timestamps()
    end
  end
  """

  alias ExOauth2Provider.{
    AccessGrants.AccessGrant,
    AccessTokens.AccessToken,
    Applications.Application
  }

  @schemas [
    {"application", Application},
    {"access_grant", AccessGrant},
    {"access_token", AccessToken}
  ]

  @spec create_schema_files(atom(), binary(), keyword()) :: any()
  def create_schema_files(context_app, namespace, opts) do
    for {table, schema} <- @schemas do
      app_base = Config.app_base(context_app)
      table_name = "#{namespace}_#{table}s"
      context = Macro.camelize(table_name)
      module = Macro.camelize("#{namespace}_#{table}")
      file = "#{Macro.underscore(module)}.ex"
      module = Module.concat([app_base, context, module])
      binary_id = Keyword.get(opts, :binary_id, false)
      macro = schema
      macro_fields = "#{table}_fields"

      content =
        EEx.eval_string(@template,
          schema: %{
            module: module,
            table: table_name,
            binary_id: binary_id,
            macro: macro,
            macro_fields: macro_fields
          },
          otp_app: context_app
        )

      dir = "lib/#{context_app}/#{Macro.underscore(context)}/"

      File.mkdir_p!(dir)

      dir
      |> Path.join(file)
      |> Generator.create_file(content)
    end
  end
end
