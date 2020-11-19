defmodule Mix.Tasks.ExOauth2Provider do
  use Mix.Task

  @shortdoc "Prints ExOauth2Provider help information"

  @moduledoc """
  Prints ExOauth2Provider tasks and their information.
      mix ex_oauth2_provider
  """

  @doc false
  def run(args) do
    case args do
      [] -> general()
      _ -> Mix.raise("Invalid arguments, expected: mix ex_oauth2_provider")
    end
  end

  defp general do
    Application.ensure_all_started(:ex_oauth2_provider)
    Mix.shell().info("ExOauth2Provider v#{Application.spec(:ex_oauth2_provider, :vsn)}")
    Mix.shell().info(Application.spec(:ex_oauth2_provider, :description))
    Mix.shell().info("\nAvailable tasks:\n")
    Mix.Tasks.Help.run(["--search", "ex_oauth2_provider."])
  end
end
