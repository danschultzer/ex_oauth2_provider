defmodule Dummy.Repo do
  @moduledoc false
  use Ecto.Repo, otp_app: :ex_oauth2_provider, adapter: Ecto.Adapters.Postgres

  def log(_cmd), do: nil
end
