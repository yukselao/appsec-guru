#!/bin/sh
exec socat -T180 TCP-LISTEN:7003,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
