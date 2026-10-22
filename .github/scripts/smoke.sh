#!/bin/sh

set -eu

case "$1" in
	/*) wallet=$1 ;;
	*) wallet=$(cd "$(dirname "$1")" && pwd)/$(basename "$1") ;;
esac

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/grin-wallet-smoke.XXXXXX")
log=$test_dir/wallet.log
: >"$log"

cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$status" -ne 0 ]; then
		cat "$log"
	fi
	rm -rf "$test_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

cd "$test_dir"
# Create a temporary testnet wallet.
if ! "$wallet" --testnet -p smoke-password init -h >"$test_dir/init.log" 2>&1; then
	echo "wallet init failed" >"$log"
	exit 1
fi

test -s grin-wallet.toml
test -s wallet_data/wallet.seed

# Check a few basic wallet commands.
"$wallet" --testnet -p smoke-password account -c smoke >>"$log" 2>&1
"$wallet" --testnet -p smoke-password account >>"$log" 2>&1
grep -qE '^ smoke +\| m/1/0( |$)' "$log"
"$wallet" --testnet -p smoke-password address >>"$log" 2>&1
grep -q tgrin1 "$log"
