#!/bin/bash
# Fixed three-component shell source suite.  Marker lines are observations;
# the real component exit statuses remain the adapter's authority.
set -u

status=0
for component in \
  test/test_ops_scripts.sh \
  test/test_real_machine_guard.sh \
  test/test_scripts.sh
do
  if /bin/bash "$component"; then
    printf 'SOURCE_GATE_COMPONENT %s PASS\n' "$component"
  else
    printf 'SOURCE_GATE_COMPONENT %s FAIL\n' "$component"
    status=1
  fi
done
exit "$status"
