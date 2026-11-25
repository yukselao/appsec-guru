#!/bin/sh
# Two listeners on one Trivy container: 7009 scans images (run.sh), 7012 scans
# IaC / Dockerfile config (run-config.sh). The api enforces the real timeout;
# -T is only a safety net.
socat -T3700 TCP-LISTEN:7012,reuseaddr,fork EXEC:/usr/local/bin/run-config.sh,pipes &
exec socat -T3700 TCP-LISTEN:7009,reuseaddr,fork EXEC:/usr/local/bin/run.sh,pipes
