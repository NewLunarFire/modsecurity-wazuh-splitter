#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

install -m 0755 -o root -g root "$SCRIPT_DIR/modsec-wazuh-split.py" /usr/local/bin/modsec-wazuh-split
sudo systemctl daemon-reload
sudo systemctl enable --now modsec-wazuh-split