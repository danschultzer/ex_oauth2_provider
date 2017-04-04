defmodule ExOauth2Provider.Mixin.Expirable do
  @moduledoc """
  Mixing macro that handles expiration.
  """

  defmacro __using__(_) do
    quote location: :keep do
      @doc """
      Filter expired data.

      ## Examples

          iex> filter_expired(data)
          data

          iex> filter_expired(expired_data)
          nil
      """
      def filter_expired(data) do
        case is_expired?(data) do
          true -> nil
          false -> data
        end
      end

      @doc """
      Checks if ectod ata has expired.

      ## Examples

          iex> is_expired?(data)
          false

          iex> is_expired?(expired_data)
          true
      """
      def is_expired?(nil), do: true
      def is_expired?(%{expires_in: expires_in, inserted_at: inserted_at} = data) do
        case expires_in do
          nil -> false
          _ ->
            expires_at = inserted_at
              |> NaiveDateTime.add(expires_in, :second)
            NaiveDateTime.compare(expires_at, NaiveDateTime.utc_now) == :lt
        end
      end
    end
  end
end
