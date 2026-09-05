#!/bin/sh
# power.sh — run amt-power with a user-provided passphrase
# Change AMT_IP to match your target machine.

AMT_IP="10.0.0.90"

printf "Enter passphrase: "
stty -echo
read -r PASSPHRASE
stty echo
printf "\n"

if [ -z "$PASSPHRASE" ]; then
  printf "Error: passphrase cannot be empty\n" >&2
  exit 1
fi

exec amt-power -ip "$AMT_IP" -passphrase "$PASSPHRASE" "$@"
