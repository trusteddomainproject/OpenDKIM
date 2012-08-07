#!/bin/sh
#
#
# (c)2010 Mike Markley <mike@markley.org>. Licensed under the same terms as the
# OpenDKIM distribution (see ../LICENSE).

force=0
while [ -n "$1" ]; do
	if [ "$1" = "-f" ]; then
		force=1
	else
		file="$1"
	fi
	shift
done

if [ -z "$file" ]; then
	echo -n "Configuration or key list file: "
	read file
fi

if [ ! -e "$file" ]; then
	echo "$0: $file: file not found" >&2
	exit 1
fi

if grep -iq "^keylist" "$file"; then
	KEYLIST="$(grep -i "^keylist" "$file" | awk '{ print $2 }')"
	echo "Found OpenDKIM configuration file; using $KEYLIST as key list file"
else
	# Assume we were passed a KeyList otherwise
	KEYLIST="$file"
fi

if [ -z "$KEYLIST" ]; then
	echo "$0: KeyList input file must be specified." >&2
	exit 1
fi

echo -n "Output file for KeyTable: "
read KEYTABLE
if [ -z "$KEYTABLE" ]; then
	echo "$0: KeyTable output file must be specified." >&2
	exit 1
fi
if [ -e "$KEYTABLE" -a $force -ne 1 ]; then
	echo "$0: refusing to overwrite $KEYTABLE" >&2
	exit 1
fi
echo -n > $KEYTABLE

echo -n "Output file for SigningTable: "
read SIGNINGTABLE
if [ -z "$SIGNINGTABLE" ]; then
	echo "$0: SigningTable output file must be specified." >&2
	exit 1
fi
if [ -e "$SIGNINGTABLE" -a $force -ne 1 ]; then
	echo "$0: refusing to overwrite $SIGNINGTABLE" >&2
	exit 1
fi
echo -n > $SIGNINGTABLE

while read line; do
	addresspat=$(echo $line | cut -d: -f1)
	domain=$(echo $line | cut -d: -f2)
	key=$(echo $line | cut -d: -f3)
	selector=$(basename $key)
	keyname="${selector}._domainkey.$domain"
	keyfile=""
	for f in "$key" "${key}.pem" "${key}.private"; do
		if [ -e "$f" ]; then
			keyfile="$f"
		fi
	done
	if [ -z "$keyfile" ]; then
		echo "Warning: Could not find private key file for $key (no privileges?)" >&2
		keyfile="$key"
	fi
	echo "$addresspat	$keyname" >> $SIGNINGTABLE
	echo "$keyname	$domain:$selector:$keyfile" >> $KEYTABLE
done < "$KEYLIST"

echo "Done; please add these options to your configuration file (and remove the KeyList entry):"
echo "KeyTable	file:$KEYTABLE"
echo "SigningTable	refile:$SIGNINGTABLE"
