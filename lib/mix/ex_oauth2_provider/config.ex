defmodule Mix.ExOauth2Provider.Config do
  @moduledoc false

  @spec update(map()) :: map()
  def update(%{config_file: config_file} = config) do
    content = config_string(config)
    source  = if File.exists?(config_file), do: File.read!(config_file), else: false

    source
    |> do_update_config(config_file, content)
    |> case do
      {:error, reason} ->
        Mix.shell.info(reason)
        Enum.into([config_string: content, log_config?: true], config)
      {:ok, reason} ->
        Mix.shell.info(reason)
        Enum.into([config_string: content, log_config?: false], config)
    end
  end
  def update(config), do: config

  @spec config_string(map()) :: binary()
  def config_string(%{repos: repos, resource_owner: resource_owner}) do
    repo = Enum.map(repos, &to_string(&1))

    """
    config :ex_oauth2_provider, ExOauth2Provider,
      repo: #{repo},
      resource_owner: #{resource_owner}
    """
  end

  defp do_update_config(source, config_file, content) do
    cond do
      source == false ->
        {:error, "Could not find #{config_file}. Configuration was not added!"}
      String.contains? source, "config :ex_oauth2_provider, ExOauth2Provider" ->
        {:error, "Configuration was not added because one already exists!"}
      true ->
        File.write!(config_file, source <> "\n" <> content)
        {:ok, "Your config/config.exs file was updated."}
    end
  end
end
