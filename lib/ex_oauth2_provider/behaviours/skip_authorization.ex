defmodule ExOauth2Provider.Behaviours.SkipAuthorization do
  @moduledoc """
  Define the rules used to determine if authorization can be skipped. If your
  app has unique criteria then implement it.

  For example:

  defmodule MyModule do
    @behaviour ExOauth2Provider.Behaviors.SkipAuthorization

    def skip_authorization(user, application) do
      user.super_cool? || application.trusted?
    end
  end
  """
  alias ExOauth2Provider.Applications.Application
  alias ExOauth2Provider.Schema

  @callback skip_authorization?(
              user :: Schema.t(),
              application :: Application.t()
            ) :: boolean()
end
