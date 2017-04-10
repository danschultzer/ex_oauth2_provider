defmodule ExOauth2Provider.Mixin.Revocable do
  @moduledoc false

  defmacro __using__(_) do
    quote location: :keep do
      @doc """
      Revoke data.

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

          iex> filter_revoked(%Data{revoked_at: nil, ...}}
          %Data{}

          iex> filter_revoked(%Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}
          nil
      """
      def filter_revoked(data) do
        case is_revoked?(data) do
          true  -> nil
          false -> data
        end
      end

      @doc """
      Checks if data has been revoked.

      ## Examples

          iex> is_revoked?(%Data{revoked_at: nil, ...}}
          false

          iex> is_revoked?(%Data{revoked_at: ~N[2017-04-04 19:21:22.292762], ...}}
          true
      """
      def is_revoked?(%{revoked_at: nil}), do: false
      def is_revoked?(_), do: true
    end
  end
end
