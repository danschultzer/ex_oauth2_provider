# ExOauth2Provider

[![Build Status](https://travis-ci.org/danschultzer/ex_oauth2_provider.svg?branch=master)](https://travis-ci.org/danschultzer/ex_oauth2_provider)

The no brainer library to use for adding OAuth 2.0 provider capabilities to your Elixir app. You can use [phoenix_oauth2_provider](https://github.com/danschultzer/phoenix_oauth2_provider) for easy integration with your Phoenix app.

## Installation

Add ExOauth2Provider to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # ...
    {:ex_oauth2_provider, "~> 0.2"}
    # ...
  ]
end
```

Run `mix deps.get` to install it, and then run the install script:

```bash
mix ex_oauth2_provider.install
```

This will add the necessary Ecto migrations to your app, and set sample configuration in `config/config.exs`.

You'll need to use a resource owner struct that already exists. This could be your User struct. If you don't have any User struct, you can add a migration like this:

```bash
mix ecto.gen.migration --change "    create table(:users) do\n      add :email, :string\n    end"
```

And use the struct in [test/support/dummy/models/user.ex](test/support/dummy/models/user.ex). The

## Authorize code flow

### Authorization request

You'll need to ensure that a resource_owner is already authenticated on these endpoints, and pass the struct as first argument in the following methods.

```elixir
# GET /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read
case ExOauth2Provider.Authorization.preauthorize(resource_owner, params) do
  {:ok, client, scopes}             -> # render authorization page
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:native_redirect, %{code: code}} -> # redirect to local :show endpoint
  {:error, error, http_status}      -> # render error page
end

# POST /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read
ExOauth2Provider.Authorization.authorize(resource_owner, params) do
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:native_redirect, %{code: code}} -> # redirect to local :show endpoint
  {:error, error, http_status}      -> # render error page
end

# DELETE /oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=CALLBACK_URL&scope=read
ExOauth2Provider.Authorization.deny(resource_owner, params) do
  {:redirect, redirect_uri}         -> # redirect to external redirect_uri
  {:error, error, http_status}      -> # render error page
end
```

### Authorization code grant

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=CALLBACK_URL
case ExOauth2Provider.Token.grant(params) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

### Revocation

```elixir
# GET /oauth/revoke?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&token=ACCESS_TOKEN
case ExOauth2Provider.Token.revoke(params) do
  {:ok, %{}}                        -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

Revocation will return `{:ok, %{}}` status even if the token is invalid.

### Other supported token grants

#### Client credentials

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=client_credentials
case ExOauth2Provider.Token.grant(params) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

#### Refresh token

Refresh tokens can be enabled in the configuration:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  repo: ExOauth2Provider.Test.Repo,
  resource_owner: Dummy.User,
  use_refresh_token: true
```

The `refresh_token` grant flow will automatically be enabled.

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=refresh_token&refresh_token=REFRESH_TOKEN
case ExOauth2Provider.Token.grant(params) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

#### Username and password

You'll need to provide an authorization method that accepts username and password as arguments, and returns `{:ok, resource_owner}` or `{:error, reason}`. Something like this:

```elixir
# Configuration in config/config.exs
config :ex_oauth2_provider, ExOauth2Provider,
  password_auth: {MyApp.MyModule, :authenticate}

# Module example
defmodule MyApp.MyModule
  def authenticate(username, password) do
    user = repo.get_by(User, email: username)
    cond do
      user == nil                       -> {:error, :no_user_found}
      check_pw(user.password, password) -> {:ok, user}
      true                              -> {:error, :invalid_password}
    end
  end
end
```

The `password` grant flow will automatically be enabled.

```elixir
# POST /oauth/token?client_id=CLIENT_ID&grant_type=password&username=USERNAME&password=PASSWORD
case ExOauth2Provider.Token.grant(params) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

## Scopes

Server wide scopes can be defined in the configuration:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  repo: ExOauth2Provider.Test.Repo,
  resource_owner: Dummy.User,
  default_scopes: ~w(public),
  optional_scopes: ~w(read update)
```

## Plug API

### ExOauth2Provider.Plug.VerifyHeader

Looks for a token in the Authorization Header. If one is not found, this does nothing.

### ExOauth2Provider.Plug.EnsureAuthenticated

Looks for a previously verified token. If one is found, continues, otherwise it will call the `:unauthenticated` function of your handler.

When you ensure a session, you can declare an error handler. This can be done as part of a pipeline or inside a Phoenix controller.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug ExOauth2Provider.Plug.EnsureAuthenticated, handler: MyApp.MyAuthErrorHandler
end
```
### ExOauth2Provider.Plug.EnsureScopes

Looks for a previously verified token. If one is found, confirms that all listed scopes are present in the token. If not, the `:unauthorized` function is called on your handler.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug ExOauth2Provider.Plug.EnsureScopes, handler: MyApp.MyAuthErrorHandler, scopes: ~w(read write)
end
```

When scopes' sets are specified through a `:one_of` map, the token is searched for at least one matching scopes set to allow the request. The first set that matches will allow the request. If no set matches, the `:unauthorized` function is called.

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug ExOauth2Provider.Plug.EnsureScopes, handler: MyApp.MyAuthErrorHandler,
    one_of: [~w(admin), ~w(read write)]
end
```

### Current resource owner and token

Access to the current resource owner and token is useful. You'll need to have run the VerifyHeader for token and resource access.

```elixir
ExOauth2Provider.Plug.current_access_token(conn) # access the token in the default location
ExOauth2Provider.Plug.current_access_token(conn, :secret) # access the token in the secret location
```

For the resource

```elixir
ExOauth2Provider.Plug.current_resource_owner(conn) # Access the loaded resource in the default location
ExOauth2Provider.Plug.current_resource_owner(conn, :secret) # Access the loaded resource in the secret location
```

### Custom access token generator

You can add your own access token generator by doing the following:

```elixir
# config/config.exs
config :ex_oauth2_provider, ExOauth2Provider,
  access_token_generator: {MyModule, :my_method}

defmodule MyModule
  def my_method(access_token) do
    %JWT.token{
      resource_owner_id: access_token.resource_owner_id,
      application_id: access_token.application.id,
      scopes: access_token.scopes,
      expires_in: access_token.expires_in,
      created_at: access_token.created_at
    }
    |> with_signer(hs256("my_secret"))
  end
end
```

Remember to change the field type for the `token` column in the `oauth_access_tokens` table to accepts tokens larger than 255 characters.

### Custom access token response body

You can add extra values to the response body.

```elixir
# config/config.exs
config :ex_oauth2_provider, ExOauth2Provider,
  access_token_response_body_handler: {MyModule, :my_method}

defmodule MyModule
  def my_method(response_body, access_token) do
    response_body
    |> Map.merge(%{user_id: access_token.resource_owner.id})
  end
end
```

Remember to change the field type for the `token` column in the `oauth_access_tokens` table to accepts tokens larger than 255 characters.

## Acknowledgement

This library was made thanks to [doorkeeper](https://github.com/doorkeeper-gem/doorkeeper), [guardian](https://github.com/ueberauth/guardian) and [authable](https://github.com/mustafaturan/authable), that gave the conceptual building blocks.

Thanks to [Benjamin Schultzer](https://github.com/schultzer) for helping refactoring the code.

## LICENSE

(The MIT License)

Copyright (c) 2017 Dan Schultzer & the Contributors Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
0
