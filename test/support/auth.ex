defmodule Dummy.Auth do
  @moduledoc false

  alias Dummy.{Users.User, Repo}

  def auth(username, password) do
    user = Repo.get_by(User, email: username)

    cond do
      user == nil                       -> {:error, :no_user_found}
      password == "secret"              -> {:ok, user}
      true                              -> {:error, :invalid_password}
    end
  end
end
