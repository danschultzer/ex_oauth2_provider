defmodule Mix.ExOauth2Provider do
  @moduledoc """
  Utilities module for mix tasks.
  """
  alias Mix.Project

  @doc """
  Raises an exception if the project is an umbrella app.
  """
  @spec no_umbrella!(binary()) :: :ok | no_return
  def no_umbrella!(task) do
    if Project.umbrella?() do
      Mix.raise("mix #{task} can only be run inside an application directory")
    end

    :ok
  end

  @doc """
  Parses argument options into a map.
  """
  @spec parse_options(OptionParser.argv(), Keyword.t(), Keyword.t()) :: {map(), OptionParser.argv(), OptionParser.errors()}
  def parse_options(args, switches, default_opts) do
    {opts, parsed, invalid} = OptionParser.parse(args, switches: switches)
    default_opts            = to_map(default_opts)
    opts                    = to_map(opts)
    config                  =
      default_opts
      |> Map.merge(opts)
      |> context_app_to_atom()

    {config, parsed, invalid}
  end

  defp to_map(keyword) do
    Enum.reduce(keyword, %{}, fn {key, value}, map ->
      case Map.get(map, key) do
        nil ->
          Map.put(map, key, value)

        existing_value ->
          value = List.wrap(existing_value) ++ [value]
          Map.put(map, key, value)
      end
    end)
  end

  defp context_app_to_atom(%{context_app: context_app} = config),
    do: Map.put(config, :context_app, String.to_atom(context_app))
  defp context_app_to_atom(config),
    do: config
end
