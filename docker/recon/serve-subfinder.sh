#!/bin/sh
exec socat -T180 TCP-LISTEN:7001,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
