defmodule ExOauth2Provider.QueryHelper do
  alias ExOauth2Provider.OauthAccessGrants.OauthAccessGrant

  def get_access_grant_by_code(code),
    do: ExOauth2Provider.repo.get_by!(OauthAccessGrant, token: code)
end
