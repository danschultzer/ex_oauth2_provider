defmodule Mix.ExOauth2Provider.Config do
  @moduledoc false

  @template """
  config :<%= context_app %>, ExOauth2Provider,
    repo: <%= repo %>,
    resource_owner: <%= resource_owner %>
  """

  @spec update(binary(), binary(), map()) :: map()
  def update(context_app, config_file, %{repos: repos, resource_owner: resource_owner}) do
    repo    = Enum.map(repos, &to_string(&1))
    content = EEx.eval_string(@template, context_app: context_app, repo: repo, resource_owner: resource_owner)
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
