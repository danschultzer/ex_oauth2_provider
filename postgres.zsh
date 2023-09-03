#!/usr/bin/env zsh
SCRIPT_DIR=$0:a:h
PG_NAME=postgres-oauth2-provider
echo " NOTE: For first time use i manually hack \"host all all all trust\" into priv/pg_data/pg_hba.conf"
echo " after the director has been initialized"
echo " then I stop this script and restart it "
docker stop $PG_NAME
docker run --rm  --name $PG_NAME -e POSTGRES_USER=$USER -e POSTGRES_PASSWORD=secret -p 5432:5432 -v $SCRIPT_DIR/priv/pg_data:/var/lib/postgresql/data  postgres


