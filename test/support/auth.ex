defmodule ExOauth2Provider.Test.Auth do
  import Ecto.Query

  def auth(username, password) do
    user = ExOauth2Provider.repo.get_by(Dummy.User, email: username)

    cond do
      user == nil                       -> {:error, :no_user_found}
      password == "secret"              -> {:ok, user}
      true                              -> {:error, :invalid_password}
    end
  end
end
