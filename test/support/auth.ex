defmodule ExOauth2Provider.Test.Auth do
  @moduledoc false

  alias Dummy.Repo

  def auth(username, password) do
    user = Repo.get_by(Dummy.Users.User, email: username)

    cond do
      user == nil                       -> {:error, :no_user_found}
      password == "secret"              -> {:ok, user}
      true                              -> {:error, :invalid_password}
    end
  end
end
