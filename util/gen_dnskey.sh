#!/bin/bash

if [ -z "$1" ]; then
	echo "Need to supply zone name"
	exit 1;
fi

if [ -z "$2" ] || [ "$2" == "ZSK" ]; then
	dnssec-keygen -a ECDSAP256SHA256 -b 256 -n ZONE $1
else
	if [ "$2" == "KSK" ]; then
		dnssec-keygen -f KSK -a ECDSAP256SHA256 -b 256 -n ZONE $1
	else
		echo "Second argument 'KSK' if you wish to generate a key signing key"
		exit 1;
	fi
fi
