defmodule ExOauth2Provider.Mixin.Scopes do
  @moduledoc false
  alias ExOauth2Provider.{Config, Scopes}
  alias Ecto.Changeset

  @spec put_scopes(Changeset.t(), binary() | nil, keyword()) :: Changeset.t()
  def put_scopes(changeset, "", config), do: put_scopes(changeset, nil, config)
  def put_scopes(changeset, default_server_scopes, config) do
    changeset
    |> Changeset.get_field(:scopes)
    |> is_empty()
    |> case do
      true -> Changeset.change(changeset, %{scopes: parse_default_scope_string(default_server_scopes, config)})
      _    -> changeset
    end
  end

  @spec validate_scopes(Changeset.t(), binary() | nil, keyword()) :: Changeset.t()
  def validate_scopes(changeset, "", config), do: validate_scopes(changeset, nil, config)
  def validate_scopes(changeset, server_scopes, config) do
    server_scopes = permitted_scopes(server_scopes, config)

    changeset
    |> Changeset.get_field(:scopes)
    |> can_use_scopes?(server_scopes, config)
    |> case do
      true -> changeset
      _    -> Changeset.add_error(changeset, :scopes, "not in permitted scopes list: #{inspect(server_scopes)}")
    end
  end

  defp is_empty(""), do: true
  defp is_empty(nil), do: true
  defp is_empty(_), do: false

  @spec parse_default_scope_string(binary() | [binary()] | nil, keyword()) :: binary()
  def parse_default_scope_string(nil, config), do: parse_default_scope_string("", config)
  def parse_default_scope_string(server_scopes, config) when is_binary(server_scopes) do
    server_scopes
    |> Scopes.to_list()
    |> parse_default_scope_string(config)
  end
  def parse_default_scope_string(server_scopes, config) do
    server_scopes
    |> Scopes.default_to_server_scopes(config)
    |> Scopes.filter_default_scopes(config)
    |> Scopes.to_string()
  end

  defp can_use_scopes?(scopes, server_scopes, config) when is_binary(scopes) do
    scopes
    |> Scopes.to_list()
    |> can_use_scopes?(server_scopes, config)
  end
  defp can_use_scopes?(scopes, server_scopes, config) when is_binary(server_scopes) do
    can_use_scopes?(scopes, Scopes.to_list(server_scopes), config)
  end
  defp can_use_scopes?(scopes, server_scopes, config) do
    server_scopes
    |> Scopes.default_to_server_scopes(config)
    |> Scopes.all?(scopes)
  end

  defp permitted_scopes(nil, config),
    do: Config.server_scopes(config)
  defp permitted_scopes(server_scopes, _config),
    do: server_scopes
end
