# ExOauth2Provider

[![Build Status](https://travis-ci.org/danschultzer/ex_oauth2_provider.svg?branch=master)](https://travis-ci.org/danschultzer/ex_oauth2_provider) [![hex.pm](http://img.shields.io/hexpm/v/ex_oauth2_provider.svg?style=flat)](https://hex.pm/packages/ex_oauth2_provider) [![hex.pm downloads](https://img.shields.io/hexpm/dt/ex_oauth2_provider.svg?style=flat)](https://hex.pm/packages/ex_oauth2_provider)

The no-brainer library to use for adding OAuth 2.0 provider capabilities to your Elixir app. You can use [phoenix_oauth2_provider](https://github.com/danschultzer/phoenix_oauth2_provider) for easy integration with your Phoenix app.

## Installation

Add ExOauth2Provider to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # ...
    {:ex_oauth2_provider, git: "git@github.com:valuechainfactory/ex_oauth2_provider.git", branch: "master"}
    # ...
  ]
end
```

Run `mix deps.get` to install it.

## Getting started

Generate the migrations and schema modules:

```bash
mix ex_oauth2_provider.install
```

Add the following to `config/config.ex`:

```elixir
config :my_app, ExOauth2Provider,
  repo: MyApp.Repo,
  resource_owner: MyApp.Users.User
```

If you don't have any user setup, you shuld consider setting up [`Pow`](https://github.com/danschultzer/pow) first.

## Authorize code flow

### Authorization request

You have to ensure that a `resource_owner` has been authenticated on the following endpoints, and pass the struct as the first argument in the following methods.

```elixir
# GET /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read
case ExOauth2Provider.Authorization.preauthorize(resource_owner, params, otp_app: :my_app) do
  {:ok, client, scopes}             -> # render authorization page
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:native_redirect, %{code: code}} -> # redirect to local :show endpoint
  {:error, error, http_status}      -> # render error page
end

# POST /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read
ExOauth2Provider.Authorization.authorize(resource_owner, params, otp_app: :my_app) do
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:native_redirect, %{code: code}} -> # redirect to local :show endpoint
  {:error, error, http_status}      -> # render error page
end

# DELETE /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read
ExOauth2Provider.Authorization.deny(resource_owner, params, otp_app: :my_app) do
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:error, error, http_status}      -> # render error page
end
```

### Authorization code grant

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=CALLBACK_URL
case ExOauth2Provider.Token.grant(params, otp_app: :my_app) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

### Revocation

```elixir
# GET /oauth/revoke?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&token=ACCESS_TOKEN
case ExOauth2Provider.Token.revoke(params, otp_app: :my_app) do
  {:ok, %{}}                        -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

Revocation will return `{:ok, %{}}` status even if the token is invalid.

### Authorization code flow in a Single Page Application

ExOauth2Provider doesn't support **implicit** grant flow. Instead you should set up an application with no client secret, and use the **Authorize code** grant flow. `client_secret` isn't required unless it has been set for the application.



#### PKCE [RFC-7637](https://datatracker.ietf.org/doc/html/rfc7636)

Enable PKCE in configuration `config/config.ex`:

```elixir
config :my_app, ExOauth2Provider,
  # ...
  # this will enable PKCE for *all* applications
  use_pkce: true
```

When `:use_pkce` is set to `:true`, PKCE is enabled globally for all apps when using the authorization code flow. It is not required or enforced. Instead, when a request comes with a `code_challenge`, we store the challenge in oauth_access_grants and use it later when granting an access token.

```elixir
# GET /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read&code_challenge=CODE_CHALLENGE&code_challenge_method=CODE_CHALLENGE_METHOD
case ExOauth2Provider.Authorization.preauthorize(resource_owner, params, otp_app: :my_app) do
  {:ok, client, scopes}             -> # render authorization page
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:native_redirect, %{code: code}} -> # redirect to local :show endpoint
  {:error, error, http_status}      -> # render error page
end
```

When making an authorization code grant request for an access token, you will need to pass a `code_verifier` as per [RFC-7637](https://datatracker.ietf.org/doc/html/rfc7636).

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=CALLBACK_URL&code_verifier=CODE_VERIFIER
case ExOauth2Provider.Token.grant(params, otp_app: :my_app) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```


### Other supported token grants

#### Client credentials

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=client_credentials
case ExOauth2Provider.Token.grant(params, otp_app: :my_app) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

#### Refresh token

Refresh tokens can be enabled in the configuration:

```elixir
config :my_app, ExOauth2Provider,
  repo: MyApp.Repo,
  resource_owner: MyApp.Users.User,
  use_refresh_token: true
```

The `refresh_token` grant flow will then be enabled.

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=refresh_token&refresh_token=REFRESH_TOKEN
case ExOauth2Provider.Token.grant(params, otp_app: :my_app) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

#### Username and password

You'll need to provide an authorization method that accepts username and password as arguments, and returns `{:ok, resource_owner}` or `{:error, reason}`. Here'a an example:

```elixir
# Configuration in config/config.exs
config :my_app, ExOauth2Provider,
  password_auth: {Auth, :authenticate}

# Module example
defmodule Auth do
  def authenticate(username, password, otp_app: :my_app) do
    User
    |> Repo.get_by(email: username)
    |> verify_password(password)
  end

  defp verify_password(nil, password) do
    check_pw("", password) # Prevent timing attack

    {:error, :no_user_found}
  end
  defp verify_password(%{password_hash: password_hash} = user, password) do
    case check_pw(password_hash, password) do
      true  -> {:ok, user}
      false -> {:error, :invalid_password}
    end
  end
end
```

The `password` grant flow will then be enabled.

```elixir
# POST /oauth/token?client_id=CLIENT_ID&grant_type=password&username=USERNAME&password=PASSWORD
case ExOauth2Provider.Token.grant(params, otp_app: :my_app) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

## Scopes

Server wide scopes can be defined in the configuration:

```elixir
config :my_app, ExOauth2Provider,
  repo: MyApp.Repo,
  resource_owner: MyApp.Users.User,
  default_scopes: ~w(public),
  optional_scopes: ~w(read update)
```
## OpenId Connect
Support for OIDC hsa been added on this fork. The scope `openid` when requested will cause an `id_token` to be generated and sent to the client.

Configuration can be added to the `ExOauth2Provider` config as:
```elixir
config :my_app, ExOauth2Provider,
  repo: MyApp.Repo,
  resource_owner: MyApp.Users.User,
  default_scopes: ~w(openid public),
  optional_scopes: ~w(read update)
  oidc: [
    # defaults to [:id]
    resource_owner_claims: [:id, :email, :msisdn, :first_name, :last_name, :gender, :avatar],
    # defaults to "https://retailpay.africa"
    issuer: "https://retailpay.africa",
    # defaults to application client_id
    audience: "some custom aud value"
  ]
  ````

  `resource_owner_claims` expects a list that will be supplied to `Map.take()` on the resource owner and will thus need to be fields defined in the `resource_owner`. Defaults to [:id].

  `aud` will default to the `client_id` of the client authorized to receive the token. It can be configured with the `audience` key.
## Plug API

### [ExOauth2Provider.Plug.VerifyHeader](lib/ex_oauth2_provider/plug/verify_header.ex)

Looks for a token in the Authorization Header. If one is not found, this does nothing. This will always be necessary to run to load access token and resource owner.

### [ExOauth2Provider.Plug.EnsureAuthenticated](lib/ex_oauth2_provider/plug/ensure_authenticated.ex)

Looks for a verified token loaded by [`VerifyHeader`](#exoauth2providerplugverifyheader). If one is not found it will call the `:unauthenticated` method in the `:handler` module.

You can use a custom `:handler` as part of a pipeline, or inside a Phoenix controller like so:

```elixir
defmodule MyAppWeb.MyController do
  use MyAppWeb, :controller

  plug ExOauth2Provider.Plug.EnsureAuthenticated,
    handler: MyAppWeb.MyAuthErrorHandler
end
```

 The `:handler` module always defaults to [ExOauth2Provider.Plug.ErrorHandler](lib/ex_oauth2_provider/plug/error_handler.ex).

### [ExOauth2Provider.Plug.EnsureScopes](lib/ex_oauth2_provider/plug/ensure_scopes.ex)

Looks for a previously verified token. If one is found, confirms that all listed scopes are present in the token. If not, the `:unauthorized` function is called on your `:handler`.

```elixir
defmodule MyAppWeb.MyController do
  use MyAppWeb, :controller

  plug ExOauth2Provider.Plug.EnsureScopes,
    handler: MyAppWeb.MyAuthErrorHandler, scopes: ~w(read write)
end
```

When scopes' sets are specified through a `:one_of` map, the token is searched for at least one matching scopes set to allow the request. The first set that matches will allow the request. If no set matches, the `:unauthorized` function is called.

```elixir
defmodule MyAppWeb.MyController do
  use MyAppWeb, :controller

  plug ExOauth2Provider.Plug.EnsureScopes,
    handler: MyAppWeb.MyAuthErrorHandler,
    one_of: [~w(admin), ~w(read write)]
end
```

### Current resource owner and access token

If the Authorization Header was verified, you'll be able to retrieve the current resource owner or access token.

```elixir
ExOauth2Provider.Plug.current_access_token(conn) # access the token in the default location
ExOauth2Provider.Plug.current_access_token(conn, :secret) # access the token in the secret location
```

```elixir
ExOauth2Provider.Plug.current_resource_owner(conn) # Access the loaded resource owner in the default location
ExOauth2Provider.Plug.current_resource_owner(conn, :secret) # Access the loaded resource owner in the secret location
```

### Custom access token generator

You can add your own access token generator, as this example shows:

```elixir
# config/config.exs
config :my_app, ExOauth2Provider,
  access_token_generator: {AccessToken, :new}

defmodule AccessToken
  def new(access_token) do
    with_signer(%JWT.token{
      resource_owner_id: access_token.resource_owner_id,
      application_id: access_token.application.id,
      scopes: access_token.scopes,
      expires_in: access_token.expires_in,
      created_at: access_token.created_at
    }, hs256("my_secret"))
  end
end
```

Remember to change the field type for the `token` column in the `oauth_access_tokens` table to accepts tokens larger than 255 characters.

### Custom access token response body

You can add extra values to the response body.

```elixir
# config/config.exs
config :my_app, ExOauth2Provider,
  access_token_response_body_handler: {CustomResponse, :response}

defmodule CustomResponse
  def response(response_body, access_token) do
    Map.merge(response_body, %{user_id: access_token.resource_owner.id})
  end
end
```

Remember to change the field type for the `token` column in the `oauth_access_tokens` table to accepts tokens larger than 255 characters.

## Using binary id

### Generate migration file with binary id

You'll need to create the migration file and schema modules with the argument `--binary-id`:

```bash
mix ex_oauth2_provider.install --binary-id
```

## ToDo
- [x] Implement OpenId Connect layer
- [ ]  Implement Proof Key for Code Exchange (PKCE)

## Acknowledgement

This library was made thanks to [doorkeeper](https://github.com/doorkeeper-gem/doorkeeper), [guardian](https://github.com/ueberauth/guardian) and [authable](https://github.com/mustafaturan/authable), that gave the conceptual building blocks.

Thanks to [Benjamin Schultzer](https://github.com/schultzer) for helping to refactor the code.

Thanks to [Kevin Ledama](https://github.com/leksim) for implementing OIDC
## LICENSE

(The MIT License)

Copyright (c) 2017-2019 Dan Schultzer & the Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
