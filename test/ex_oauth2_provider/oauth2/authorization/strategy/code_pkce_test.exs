defmodule ExOauth2Provider.Authorization.CodePkceTest do
  use ExOauth2Provider.TestCase

  alias ExOauth2Provider.Authorization
  alias ExOauth2Provider.Test.Fixtures
  alias Dummy.{OauthAccessGrants.OauthAccessGrant, Repo}

  @code_challenge "1234567890abcdefrety1234567890abcdefrety.~-_"
  @s256_code_challenge :crypto.hash(:sha256, @code_challenge) |> Base.url_encode64(padding: false)
  @client_id "Jf5rM8hQBc"
  @missing_code_challenge_request %{
    "client_id" => @client_id,
    "response_type" => "code",
    "scope" => "app:read app:write"
  }
  @valid_plain_request Map.merge(@missing_code_challenge_request, %{
                         "code_challenge" => @code_challenge
                       })
  @valid_explicit_plain_request Map.merge(@missing_code_challenge_request, %{
                                  "code_challenge" => @code_challenge,
                                  "code_challenge_method" => "plain"
                                })
  @valid_s256_request Map.merge(@missing_code_challenge_request, %{
                        "code_challenge" => @s256_code_challenge,
                        "code_challenge_method" => "S256"
                      })
  @invalid_request %{
    error: :invalid_request,
    error_description:
      "The request is missing a required parameter, includes an unsupported parameter value, or is otherwise malformed."
  }

  setup_all %{} do
    new_conf = Application.get_env(:ex_oauth2_provider, ExOauth2Provider) ++ [use_pkce: true]
    Application.put_env(:ex_oauth2_provider, ExOauth2Provider, new_conf)

    :ok
  end

  setup do
    resource_owner = Fixtures.resource_owner()
    application = Fixtures.application(uid: @client_id, scopes: "app:read app:write")
    {:ok, %{resource_owner: resource_owner, application: application}}
  end

  test "#preauthorize/3 missing code_challenge", %{resource_owner: resource_owner} do
    assert Authorization.preauthorize(resource_owner, @missing_code_challenge_request,
             otp_app: :ex_oauth2_provider
           ) == {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 missing code_challenge", %{resource_owner: resource_owner} do
    assert Authorization.authorize(resource_owner, @missing_code_challenge_request,
             otp_app: :ex_oauth2_provider
           ) == {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 invalid code_challenge_method", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_plain_request, %{"code_challenge_method" => "invalid"})

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 invalid plain code_challenge", %{resource_owner: resource_owner} do
    request =
      Map.merge(@valid_plain_request, %{
        "code_challenge" => @code_challenge <> "<<bad_character>>"
      })

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 invalid s256 code_challenge", %{resource_owner: resource_owner} do
    request = Map.merge(@valid_s256_request, %{"code_challenge" => @s256_code_challenge <> "baddecode"})

    assert Authorization.authorize(resource_owner, request, otp_app: :ex_oauth2_provider) ==
             {:error, @invalid_request, :bad_request}
  end

  test "#authorize/3 implicit plain code_challenge_method generates grant", %{
    resource_owner: resource_owner
  } do
    assert {:native_redirect, %{code: code}} =
             Authorization.authorize(resource_owner, @valid_plain_request,
               otp_app: :ex_oauth2_provider
             )

    owner_id = resource_owner.id

    assert %{
             resource_owner_id: ^owner_id,
             code_challenge: @code_challenge,
             code_challenge_method: "plain",
             scopes: "app:read app:write"
           } = Repo.get_by(OauthAccessGrant, token: code)
  end

  test "#authorize/3 explicit plain code_challenge_method generates grant", %{
    resource_owner: resource_owner
  } do
    assert {:native_redirect, %{code: code}} =
             Authorization.authorize(resource_owner, @valid_explicit_plain_request,
               otp_app: :ex_oauth2_provider
             )

    owner_id = resource_owner.id

    assert %{
             resource_owner_id: ^owner_id,
             code_challenge: @code_challenge,
             code_challenge_method: "plain",
             scopes: "app:read app:write"
           } = Repo.get_by(OauthAccessGrant, token: code)
  end

  test "#authorize/3 S256 code_challenge_method generates grant", %{
    resource_owner: resource_owner
  } do
    assert {:native_redirect, %{code: code}} =
             Authorization.authorize(resource_owner, @valid_s256_request,
               otp_app: :ex_oauth2_provider
             )

    owner_id = resource_owner.id

    assert %{
             resource_owner_id: ^owner_id,
             code_challenge: @s256_code_challenge,
             code_challenge_method: "S256",
             scopes: "app:read app:write"
           } = Repo.get_by(OauthAccessGrant, token: code)
  end
end
