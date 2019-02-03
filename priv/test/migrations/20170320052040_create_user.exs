defmodule ExOauth2Provider.Test.Repo.Migrations.CreateUser do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: is_nil(System.get_env("UUID"))) do
      if System.get_env("UUID") do
        add :id, :uuid, primary_key: true
      end
      add :email, :string

      timestamps()
    end
  end
end
