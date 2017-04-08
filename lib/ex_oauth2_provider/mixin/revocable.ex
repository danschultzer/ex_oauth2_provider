defmodule ExOauth2Provider.Mixin.Revocable do
  @moduledoc """
  Mixing macro that handles revocation.
  """

  defmacro __using__(_) do
    quote location: :keep do
      @doc """
      Updates revoke_at on ecto data.

      ## Examples

          iex> revoke(data)
          {:ok, %Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}

          iex> revoke(invalid_data)
          {:error, %Ecto.Changeset{}}
      """
      def revoke(%{revoked_at: nil} = data) do
        changeset = Ecto.Changeset.change data, revoked_at: NaiveDateTime.utc_now
        ExOauth2Provider.repo.update(changeset)
      end
      def revoke(%{revoked_at: _} = data), do: {:ok, data}

      @doc """
      Filter revoked data.

      ## Examples

          iex> filter_revoked(data)
          data

          iex> filter_revoked(revoked_data)
          nil
      """
      def filter_revoked(data) do
        case is_revoked?(data) do
          true -> nil
          false -> data
        end
      end

      @doc """
      Checks if ecto data has been revoked.

      ## Examples

          iex> is_revoked?(data)
          false

          iex> is_revoked?(revoked_data)
          true
      """
      def is_revoked?(%{revoked_at: nil}), do: false
      def is_revoked?(_), do: true
    end
  end
end
