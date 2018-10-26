# ExOauth2Provider

[![Build Status](https://travis-ci.org/danschultzer/ex_oauth2_provider.svg?branch=master)](https://travis-ci.org/danschultzer/ex_oauth2_provider) [![hex.pm](http://img.shields.io/hexpm/v/ex_oauth2_provider.svg?style=flat)](https://hex.pm/packages/ex_oauth2_provider) [![hex.pm downloads](https://img.shields.io/hexpm/dt/ex_oauth2_provider.svg?style=flat)](https://hex.pm/packages/ex_oauth2_provider)

The no-brainer library to use for adding OAuth 2.0 provider capabilities to your Elixir app. You can use [phoenix_oauth2_provider](https://github.com/danschultzer/phoenix_oauth2_provider) for easy integration with your Phoenix app.

## Installation

Add ExOauth2Provider to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # ...
    {:ex_oauth2_provider, "~> 0.4.3"}
    # ...
  ]
end
```

Run `mix deps.get` to install it, and then run the install script:

```bash
mix ex_oauth2_provider.install
```

This will add the necessary Ecto migrations to your app, and set sample configuration in `config/config.exs`.

You are required to use a resource owner struct that already exists. This could be your `User` struct. If you don't have any `User` struct, you can create a migration with this:

```bash
mix ecto.gen.migration create_users --change $'    create table(:users) do\n      add :email, :string\n    end'
```

And use the struct in [test/support/dummy/models/user.ex](test/support/dummy/models/user.ex).

If you're not using auto incremental integer (`:id`) for your primary key(s), please read the [Using UUID or custom primary key type](#using-uuid-or-custom-primary-key-type) section.

## Authorize code flow

### Authorization request

You have to ensure that a `resource_owner` has been authenticated on the following endpoints, and pass the struct as the first argument in the following methods.

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

### Authorization code flow in a Single Page Application

ExOauth2Provider doesn't support **implicit** grant flow. Instead you should set up an application with no client secret, and use the **Authorize code** grant flow. `client_secret` isn't required unless it has been set for the application.

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

The `refresh_token` grant flow will then be enabled.

```elixir
# POST /oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=refresh_token&refresh_token=REFRESH_TOKEN
case ExOauth2Provider.Token.grant(params) do
  {:ok, access_token}               -> # JSON response
  {:error, error, http_status}      -> # JSON response
end
```

#### Username and password

You'll need to provide an authorization method that accepts username and password as arguments, and returns `{:ok, resource_owner}` or `{:error, reason}`. Here'a an example:

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

The `password` grant flow will then be enabled.

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

### [ExOauth2Provider.Plug.VerifyHeader](lib/ex_oauth2_provider/plug/verify_header.ex)

Looks for a token in the Authorization Header. If one is not found, this does nothing. This will always be necessary to run to load access token and resource owner.

### [ExOauth2Provider.Plug.EnsureAuthenticated](lib/ex_oauth2_provider/plug/ensure_authenticated.ex)

Looks for a verified token loaded by [`VerifyHeader`](#exoauth2providerplugverifyheader). If one is not found it will call the `:unauthenticated` method in the `:handler` module.

You can use a custom `:handler` as part of a pipeline, or inside a Phoenix controller like so:

```elixir
defmodule MyApp.MyController do
  use MyApp.Web, :controller

  plug ExOauth2Provider.Plug.EnsureAuthenticated, handler: MyApp.MyAuthErrorHandler
end
```

 The `:handler` module always defaults to [ExOauth2Provider.Plug.ErrorHandler](lib/ex_oauth2_provider/plug/error_handler.ex).

### [ExOauth2Provider.Plug.EnsureScopes](lib/ex_oauth2_provider/plug/ensure_scopes.ex)

Looks for a previously verified token. If one is found, confirms that all listed scopes are present in the token. If not, the `:unauthorized` function is called on your `:handler`.

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

## Using UUID or custom primary key type

### 1. If only resource owner uses `:uuid`

You'll need to create the migration file with the argument `--uuid resource_owners`:

```bash
mix ex_oauth2_provider.install --uuid resource_owners
```

And set the config to use `:binary_id` for `belongs_to` fields:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  resource_owner: {Dummy.User, :binary_id}
```

### 2. If all structs should use `:uuid`

If you don't have auto-incrementing integers as primary keys in your database you can set up `ExOauth2Provider` to handle all primary keys as `:uuid` by doing the following.

Update the `:ex_oauth2_provider` config in `config/config.exs` to use the the [UUID schema](lib/ex_oauth2_provider/schemas/uuid.ex) macro:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  resource_owner: {Dummy.User, :binary_id},
  app_schema: ExOauth2Provider.Schema.UUID
```

And generate a migration file that uses `:uuid` for all tables:

```bash
mix ex_oauth2_provider.install --uuid all
```

### 3. If you need something different than `:uuid`

It's also possible to use a completely different setup by adding a custom schema macro, however you'll need to ensure that the schema file is compiled before this library and that you've updated the migration file accordingly.

### 4. If you need custom `belongs_to` options for resource owner

You can provide a list of `belongs_to` options, by passing a keyword list instead. This is useful when you want to use a `references` value:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  resource_owner: {Dummy.User, [type: :binary_id, references: :uuid]}
```

## Acknowledgement

This library was made thanks to [doorkeeper](https://github.com/doorkeeper-gem/doorkeeper), [guardian](https://github.com/ueberauth/guardian) and [authable](https://github.com/mustafaturan/authable), that gave the conceptual building blocks.

Thanks to [Benjamin Schultzer](https://github.com/schultzer) for helping to refactor the code.

## LICENSE

(The MIT License)

Copyright (c) 2017 Dan Schultzer & the Contributors Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the 'Software'), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
