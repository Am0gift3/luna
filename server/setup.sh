#!bin/bash
sudo useradd -r -s /usr/sbin/nologin -d /opt/pentest-api pentest
sudo mkdir -p /opt/pentest-api
sudo chown pentest:pentest /opt/pentest-api
sudo tee /etc/sudoers.d/pentest-api <<'EOF'
# Pentest API: whitelist privileged tools only
Cmnd_Alias PENTEST_PRIV = \
    /usr/bin/masscan, \
    /usr/bin/aircrack-ng, \
    /usr/bin/airodump-ng, \
    /usr/bin/airmon-ng, \
    /usr/bin/wifite, \
    /usr/bin/responder

pentest ALL=(root) NOPASSWD: PENTEST_PRIV
Defaults:pentest !requiretty
EOF
sudo chmod 0440 /etc/sudoers.d/pentest-api
sudo visudo -c   # verify syntax
