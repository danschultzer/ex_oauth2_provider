defmodule ExOauth2Provider.Features do
  @moduledoc """
  Determine the status of configurable features.
  """
  @behaviour ExOauth2Provider.Behaviours.SkipAuthorization

  def skip_authorization?(_user, _application), do: false
end
