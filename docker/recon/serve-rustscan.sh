#!/bin/sh
exec socat -T300 TCP-LISTEN:7004,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
