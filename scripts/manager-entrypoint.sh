#!/usr/bin/env bash
set -euo pipefail
if [[ -d /var/ossec/data_tmp ]]; then
  bash /etc/cont-init.d/0-wazuh-init
else
  cp /wazuh-config-mount/etc/ossec.conf /var/ossec/etc/ossec.conf
  cp /wazuh-config-mount/etc/rules/edr_lab_rules.xml /var/ossec/etc/rules/edr_lab_rules.xml
fi
/var/ossec/bin/wazuh-control start
tail -F /var/ossec/logs/ossec.log &
log_pid=$!
trap '/var/ossec/bin/wazuh-control stop; kill "$log_pid" 2>/dev/null || true' TERM INT
wait "$log_pid"
