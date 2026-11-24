#!/bin/sh
exec socat -T3700 TCP-LISTEN:7011,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
