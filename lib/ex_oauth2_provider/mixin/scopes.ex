defmodule ExOauth2Provider.Mixin.Scopes do
  @moduledoc false
  alias ExOauth2Provider.{Config, Scopes}
  alias Ecto.Changeset

  defmacro __using__(_) do
    quote location: :keep do
      @spec put_scopes(Changeset.t()) :: Changeset.t()
      def put_scopes(%{} = changeset), do: put_scopes(changeset, nil)
      def put_scopes(%{} = changeset, ""), do: put_scopes(changeset, nil)
      def put_scopes(%{} = changeset, default_server_scopes) do
        changeset
        |> Changeset.get_field(:scopes)
        |> is_empty()
        |> case do
          true -> Changeset.change(changeset, %{scopes: parse_default_scope_string(default_server_scopes)})
          _    -> changeset
        end
      end

      @spec validate_scopes(Changeset.t()) :: Changeset.t()
      def validate_scopes(%{} = changeset), do: validate_scopes(changeset, nil)
      def validate_scopes(%{} = changeset, ""), do: validate_scopes(changeset, nil)
      def validate_scopes(%{} = changeset, server_scopes) do
        server_scopes = permitted_scopes(server_scopes)

        changeset
        |> Changeset.get_field(:scopes)
        |> can_use_scopes?(server_scopes)
        |> case do
          true -> changeset
          _    -> Changeset.add_error(changeset, :scopes, "not in permitted scopes list: #{inspect(server_scopes)}")
        end
      end

      defp is_empty(""), do: true
      defp is_empty(nil), do: true
      defp is_empty(_), do: false

      @spec parse_default_scope_string(binary() | nil) :: binary()
      def parse_default_scope_string(nil), do: parse_default_scope_string("")
      def parse_default_scope_string(server_scopes) when is_binary(server_scopes) do
        server_scopes
        |> Scopes.to_list()
        |> parse_default_scope_string()
      end
      def parse_default_scope_string(server_scopes) do
        server_scopes
        |> Scopes.default_to_server_scopes()
        |> Scopes.filter_default_scopes()
        |> Scopes.to_string()
      end

      defp can_use_scopes?(scopes, server_scopes) when is_binary(scopes) do
        scopes
        |> Scopes.to_list()
        |> can_use_scopes?(server_scopes)
      end
      defp can_use_scopes?(scopes, server_scopes) when is_binary(server_scopes) do
        can_use_scopes?(scopes, Scopes.to_list(server_scopes))
      end
      defp can_use_scopes?(scopes, server_scopes) do
        server_scopes
        |> Scopes.default_to_server_scopes()
        |> Scopes.all?(scopes)
      end

      defp permitted_scopes(nil),
        do: Config.server_scopes()
      defp permitted_scopes(server_scopes),
        do: server_scopes
    end
  end
end
