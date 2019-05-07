defmodule Mix.ExOauth2Provider.Config do
  @moduledoc false

  @template """
  config :<%= app %>, <%= inspect key %><%= for {key, value} <- opts do %>,
    <%= key %>: <%= value %><% end %>
  """

  @spec update(binary(), binary(), keyword()) :: map()
  def update(config_file, context_app, opts, key \\ ExOauth2Provider) do
    content = EEx.eval_string(@template, app: context_app, key: key, opts: opts)
    source  = if File.exists?(config_file), do: File.read!(config_file), else: false

    source
    |> do_update_config(config_file, content, context_app)
    |> case do
      {:error, reason} -> Mix.shell.info(reason)
      {:ok, reason}    -> Mix.shell.info(reason)
    end
  end

  defp do_update_config(source, config_file, content, context_app) do
    cond do
      source == false ->
        {:error, "Could not find #{config_file}. Configuration was not added!"}
      String.contains? source, "config :#{context_app}, ExOauth2Provider" ->
        {:error, "Configuration was not added because one already exists!"}
      true ->
        File.write!(config_file, source <> "\n" <> content)
        {:ok, "Your config/config.exs file was updated."}
    end
  end
end
