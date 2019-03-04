defmodule ExOauth2Provider.Mix.TestCase do
  @moduledoc false
  use ExUnit.CaseTemplate

  setup context do
    current_shell = Mix.shell()

    on_exit fn ->
      Mix.shell(current_shell)
    end

    Mix.shell(Mix.Shell.Process)

    context
  end
end
