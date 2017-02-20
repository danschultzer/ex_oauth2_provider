# ExOauth2Provider

The no brainer library to add OAuth 2 provider functionality to your elixir or phoenix app.

## Installation

Add ExOauth2Provider to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    # ...
    {:ex_oauth2_provider, "~> 0.1.0"}
    # ...
  ]
end
```

Run `mix deps.get` to install it. Add the following to `config/config.exs`:

```elixir
config :ex_oauth2_provider, ExOauth2Provider,
  repo: MyApp.Repo,
  resource_owner_model: MyApp.User
```

You should use a resource owner model that already exists in your app, like your user model. If you don't have nay user model, you can add a migration like this:

```bash
mix ecto.gen.migration --change "    create table(:users) do\n      add :refresh_token, :string\n    end"
```

And use the model in [test/support/dummy/models/user.ex](test/support/dummy/models/user.ex).

3. Add migrations

```bash
mix ex_oath2_provider.install
```

This will add all necessary migrations to your app.
