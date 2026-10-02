# test/run_all.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
out="$(bash "$ROOT/test/run_all.sh" 2>&1)"; rc=$?
fails=0
echo "$out" | grep -q "current-env clean" || { echo "NOT ok - 缺 current-env 判定"; fails=1; }
echo "$out" | grep -q "release-ready green" || { echo "NOT ok - 缺 release-ready 判定"; fails=1; }
echo "$out" | grep -qE "offline|loopback|scripts|rust|frontend" || { echo "NOT ok - 缺分层汇总"; fails=1; }
[ "$fails" -eq 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
