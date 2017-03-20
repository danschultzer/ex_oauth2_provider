defmodule ExOauth2Provider.Test.Repo.Migrations.CreateUser do
  use Ecto.Migration

  def change do
    create table(:users) do
      add :email, :string
      timestamps()
    end
  end
end
