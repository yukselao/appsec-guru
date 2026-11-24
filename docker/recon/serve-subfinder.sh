#!/bin/sh
# The api enforces the idle and stage limits (Settings); -T is only a safety net.
exec socat -T3700 TCP-LISTEN:7001,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
