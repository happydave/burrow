#!/bin/sh
# Stand-in for a server's client-connect allowlist: admit a CN only if listed.
# shellcheck disable=SC2154 # common_name, trusted_ip and local_port_1 come from openvpn's environment
echo "$(date +%T) client-connect cn=$common_name ip=$trusted_ip port=$local_port_1" >> /log/connect.log
grep -qx "$common_name" /etc/openvpn/allowed && exit 0
echo "$(date +%T) rejected cn=$common_name" >> /log/connect.log
exit 1
