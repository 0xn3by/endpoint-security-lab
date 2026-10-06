#!/usr/bin/env bash
set -euo pipefail
bash /etc/cont-init.d/0-wazuh-init
# Only the disposable contract container is changed. CLI logtest uses JSON decoding.
sed -i 's@<decoded_as>windows_eventchannel</decoded_as>@<decoded_as>json</decoded_as>@' /var/ossec/ruleset/rules/0575-win-base_rules.xml
sed -i '/<category>ossec<\/category>/d' /var/ossec/ruleset/rules/0575-win-base_rules.xml
/var/ossec/bin/wazuh-control start
exec tail -F /var/ossec/logs/ossec.log
