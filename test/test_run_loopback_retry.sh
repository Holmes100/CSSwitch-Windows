# test/run-loopback.sh 的有界重试逻辑（离线、确定性，不跑真实 4 个 loopback 模块）。
# 注：本文件尚未接入任何层 runner（run-scripts.sh 等），是否接入留待 Task 10 / 终审决定。
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fails=0

# (a) 恒失败桩 → 应耗尽 3 次尝试，末行 fail，rc=1
out_a="$(cd "$ROOT" && CSSWITCH_LOOPBACK_TEST_CMD='false' bash test/run-loopback.sh 2>&1)"; rc_a=$?
attempts_a="$(echo "$out_a" | grep -c '^loopback 尝试 ')"
[ "$rc_a" -eq 1 ] || { echo "NOT ok - 恒失败桩 rc 应为 1, 实际 $rc_a"; fails=1; }
echo "$out_a" | grep -qE '^S0_LAYER loopback fail$' || { echo "NOT ok - 恒失败桩缺 S0_LAYER loopback fail"; fails=1; }
[ "$attempts_a" -eq 2 ] || { echo "NOT ok - 恒失败桩应有 2 条重试提示, 实际 $attempts_a"; fails=1; }

# (b) 第 3 次尝试通过桩 → 前两次失败提示 + 末行 pass，rc=0
CNT="$(mktemp)"; printf 0 > "$CNT"
out_b="$(cd "$ROOT" && CSSWITCH_LOOPBACK_TEST_CMD='n=$(cat '"$CNT"'); n=$((n+1)); printf %s "$n" > '"$CNT"'; [ "$n" -ge 3 ]' bash test/run-loopback.sh 2>&1)"; rc_b=$?
rm -f "$CNT"
attempts_b="$(echo "$out_b" | grep -c '^loopback 尝试 ')"
[ "$rc_b" -eq 0 ] || { echo "NOT ok - 第3次通过桩 rc 应为 0, 实际 $rc_b"; fails=1; }
echo "$out_b" | grep -qE '^S0_LAYER loopback pass$' || { echo "NOT ok - 第3次通过桩缺 S0_LAYER loopback pass"; fails=1; }
[ "$attempts_b" -eq 2 ] || { echo "NOT ok - 第3次通过桩应有 2 条重试提示, 实际 $attempts_b"; fails=1; }
echo "$out_b" | grep -q '第 3 次尝试通过' || { echo "NOT ok - 第3次通过桩缺「通过」提示行"; fails=1; }

[ "$fails" -eq 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
