
# install deps

mix deps.get
mix deps.compile



# setup postgresql 

 Running postgresql via Docker can make setting up tests simple.
 
 However because postgresql is run inside the docker host, any connections to it invoke
 the access control file "pg_hba.conf"
 
 A simple way to set docker postgresql up for tests is to use the below script
 and then stop the script, modifiy the pg_hba.conf and then restart the script.
 
 This is fine for development but no production machine should trust any user incoming.

 1) start postgres via script (will download and run image)
 2) stop the script (CTRL-C)
 3) change last line of priv/pg_data/pg_hba.conf to "host all all all trust"
 4) restart postgres via script

```
#!/usr/bin/env zsh
SCRIPT_DIR=$0:a:h
PG_NAME=postgres-oauth2-provider
mkdir -p $SCRIPT_DIR/priv/pg_data
docker stop $PG_NAME
docker run --rm  --name $PG_NAME -e POSTGRES_USER=$USER -e POSTGRES_PASSWORD=secret -p 5432:5432 -v $SCRIPT_DIR/priv/pg_data:/var/lib/postgresql/data  postgres

```

# running tests


```
mix clean && mix test
```


UUID test needs clean compilation.
```
mix clean && UUID=1 mix tes
```
