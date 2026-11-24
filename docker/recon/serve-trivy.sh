#!/bin/sh
# The api enforces the real timeout; -T is only a safety net.
exec socat -T3700 TCP-LISTEN:7009,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
