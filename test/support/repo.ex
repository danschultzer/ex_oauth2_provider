defmodule ExOauth2Provider.Test.Repo do
  use Ecto.Repo, otp_app: :ex_oauth2_provider

  def log(_cmd), do: nil
end
