#!/bin/sh
# 7010 scans a submitted manifest; 7013 scans a live cluster (kubeconfig streamed).
socat -T3700 TCP-LISTEN:7013,reuseaddr,fork EXEC:/usr/local/bin/run-cluster.sh,pipes &
exec socat -T3700 TCP-LISTEN:7010,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
