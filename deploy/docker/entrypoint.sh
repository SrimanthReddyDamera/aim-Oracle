#!/bin/bash
# =============================================================================
# ORACLE Container Entrypoint Dispatcher (Brick 4.6)
# Handles graceful shutdown (SIGTERM / SIGINT) and component routing
# =============================================================================

set -e

# Forward signals to child process
pid=0
term_handler() {
    echo "[ORACLE Entrypoint] Received termination signal (SIGTERM/SIGINT). Forwarding to PID $pid..."
    if [ $pid -ne 0 ]; then
        kill -SIGTERM "$pid" 2>/dev/null || true
        wait "$pid"
    fi
    echo "[ORACLE Entrypoint] Process exited cleanly."
    exit 0
}

trap 'term_handler' SIGTERM SIGINT

COMPONENT="${1:-api}"

case "$COMPONENT" in
    api)
        echo "[ORACLE] Launching API Ingress Server on 0.0.0.0:8000..."
        exec python -m uvicorn backend.release.ingress:create_ingress_app --factory --host 0.0.0.0 --port 8000 &
        pid=$!
        wait "$pid"
        ;;
    worker)
        WORKER_ID="${ORACLE_NODE_ID:-worker-$(hostname)}"
        echo "[ORACLE] Launching Distributed Worker Node ($WORKER_ID)..."
        exec python -c "
import sys, time
from backend.release.persistence.factory import PersistenceFactory
from backend.release.distributed.coordinator import DistributedWorkerCoordinator
from backend.release.distributed.lock import DatabaseDistributedLockProvider, RedisDistributedLockProvider
from backend.release.config import EnterpriseRuntimeConfig

cfg = EnterpriseRuntimeConfig.from_env()
store = PersistenceFactory.create_bundle()
lock_prov = DatabaseDistributedLockProvider(store.locks)

coordinator = DistributedWorkerCoordinator(store=store, lock_provider=lock_prov, node_id='$WORKER_ID')
coordinator.start()
print('[Worker $WORKER_ID] Worker node active and polling leases.')
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    coordinator.stop()
" &
        pid=$!
        wait "$pid"
        ;;
    scheduler)
        echo "[ORACLE] Launching Distributed Scheduler Daemon..."
        exec python -c "
import sys, time
from backend.release.persistence.factory import PersistenceFactory
from backend.release.distributed.scheduler import DistributedScheduler
from backend.release.distributed.lock import DatabaseDistributedLockProvider
from backend.release.drift import ContinuousDriftMonitor

store = PersistenceFactory.create_bundle()
lock_prov = DatabaseDistributedLockProvider(store.locks)
drift_mon = ContinuousDriftMonitor(store)
sched = DistributedScheduler(store=store, lock_provider=lock_prov, drift_monitor=drift_mon, interval_seconds=15.0)
sched.start()
print('[Scheduler] Distributed scheduler active and acquiring leader lock.')
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    sched.stop()
" &
        pid=$!
        wait "$pid"
        ;;
    cli)
        shift
        echo "[ORACLE] Executing CLI command: oracle $*"
        exec python -m backend.release.cli "$@"
        ;;
    *)
        exec "$@"
        ;;
esac
