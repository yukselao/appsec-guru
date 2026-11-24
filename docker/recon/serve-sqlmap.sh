#!/bin/sh
# The api enforces the real stage timeout; -T is only a safety net.
exec socat -T3700 TCP-LISTEN:7007,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
