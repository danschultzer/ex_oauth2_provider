defmodule ExOauth2Provider.Plug.LoadResource do
  @moduledoc """
  Fetches the resource tied to the token.
  The current resource is loaded by calling `from_token/1` on your
  `ExOauth2Provider.Serializer` with the value of the `sub` claim. See the `:serializer`
  option for more details.
  If the resource is loaded successfully, it is accessible by calling
  `ExOauth2Provider.Plug.current_resource/2`.
  If there is no valid access token in the request so far (`ExOauth2Provider.Plug.VerifySession`
  / `ExOauth2Provider.Plug.VerifyHeader`) did not find a valid token
  then nothing will occur, and `ExOauth2Provider.Plug.current_resource/2` will be nil.
  ## Options
    * `:serializer` - The serializer to use to load the current resource from
        the subject claim of the token. Defaults to the result of
        `ExOauth2Provider.serializer/0`.
  """

  @doc false
  def init(opts \\ %{}), do: Enum.into(opts, %{})

  @doc false
  def call(conn, opts) do
    key = Map.get(opts, :key, :default)

    case ExOauth2Provider.Plug.current_resource(conn, key) do
      nil ->
        case ExOauth2Provider.Plug.current_token(conn, key) do
          nil -> conn
          token -> load_resource(token, opts) |> put_current_resource(conn, key)
        end
      _ -> conn
    end
  end

  defp put_current_resource({:ok, resource}, conn, key) do
    ExOauth2Provider.Plug.set_current_resource(conn, resource, key)
  end

  defp put_current_resource({:error, _}, conn, key) do
    ExOauth2Provider.Plug.set_current_resource(conn, nil, key)
  end

  defp load_resource(token, opts) do
    case ExOauth2Provider.repo.preload(token, :resource_owner).resource_owner do
      resource -> { :ok, resource }
      _ -> { :error, :no_association_found }
    end
  end

  defp get_resource_association(opts) do
    :user
  end

  # defp get_resource_association(opts) do
  #   Map.get(opts, :resource_association, ExOauth2Provider.resource_association)
  # end
end
