#!/bin/bash

# Run "setup.py develop" if we need to (can be the case if the .egg-info paths get removed, or mounted over, e.g. fednode)
if [ ! -d /dogeparty-lib/dogeparty_lib.egg-info ]; then
    cd /dogeparty-lib; python3 setup.py develop; cd /
fi
if [ ! -d /dogeparty-cli/dogeparty_cli.egg-info ]; then
    cd /dogeparty-cli; python3 setup.py develop; cd /
fi

# Bootstrap if the database does not exist (do this here to handle cases
# where a volume is mounted over the share dir, like the fednode docker compose config does...)
if ([ -z "$2" ] || [ $2 != "true" ]); then
    if [ ! -f /root/.local/share/dogeparty/dogeparty.db ] && [ $1 = "mainnet" ]; then
        echo "Downloading mainnet bootstrap DB..."
        dogeparty-server bootstrap --quiet
        PARAMS="${PARAMS} --checkdb"
    fi
    if [ ! -f /root/.local/share/dogeparty/dogeparty.testnet.db ] && [ $1 = "testnet" ]; then
        echo "Downloading testnet bootstrap DB..."
        dogeparty-server --testnet bootstrap --quiet
        PARAMS="${PARAMS} --checkdb"
    fi
fi

# Kick off the server, defaulting to the "start" subcommand
# Launch utilizing the SIGTERM/SIGINT propagation pattern from
# http://veithen.github.io/2014/11/16/sigterm-propagation.html
: ${PARAMS:=""}
: ${COMMAND:="start"}

trap 'kill -TERM $PID' TERM INT
/usr/local/bin/dogeparty-server ${PARAMS} ${COMMAND} &
PID=$!
wait $PID
trap - TERM INT
wait $PID
EXIT_STATUS=$?
