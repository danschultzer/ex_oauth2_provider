defmodule Mix.Tasks.ExOauth2Provider do
  use Mix.Task
  alias Mix.Tasks.Help

  @shortdoc "Prints ExOauth2Provider help information"

  @moduledoc """
  Prints ExOauth2Provider tasks and their information.
      mix ex_oauth2_provider
  """

  @doc false
  def run(args) do
    {_opts, args, _} = OptionParser.parse(args, switches: [])

    validate_args(args)
  end
  defp validate_args([]), do: general()
  defp validate_args(_), do: Mix.raise "Invalid arguments, expected: mix ex_oauth2_provider"

  defp general do
    Application.ensure_all_started(:ex_oauth2_provider)
    Mix.shell.info "ExOauth2Provider v#{Application.spec(:ex_oauth2_provider, :vsn)}"
    Mix.shell.info Application.spec(:ex_oauth2_provider, :description)
    Mix.shell.info "\nAvailable tasks:\n"
    Help.run(["--search", "ex_oauth2_provider."])
  end
end
