defmodule ExOauth2Provider.Test.Repo.Migrations.AddFieldToApplication do
  use Ecto.Migration

  def change do
    alter table(:oauth_applications) do
      add(:description, :text)
      add(:reference, :uuid)
    end
  end
end
