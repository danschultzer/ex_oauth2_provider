#!/usr/bin/env zsh
SCRIPT_DIR=$0:a:h
DATA_DIR=$SCRIPT_DIR/../priv/pg_data
PG_NAME=postgres-oauth2-provider
mkdir -p $DATA_DIR
docker stop $PG_NAME
docker run --rm  --name $PG_NAME -e POSTGRES_USER=$USER -e POSTGRES_PASSWORD=secret -p 5432:5432 -v $DATA_DIR:/var/lib/postgresql/data  postgres

