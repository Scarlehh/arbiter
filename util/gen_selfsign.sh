#!/bin/bash

if [ -z "$1" ]; then
	echo "Need to supply cert name"
else
	if [ -z "$2" ]; then
		echo "Generating ECDSAP256SHA256 key"
		openssl req -new -x509 -nodes -days 365 \
				-newkey ec:<(openssl ecparam -name prime256v1) \
				-keyout $1.key \
				-out $1.crt
	else
		openssl req -new -x509 -days 365 \
				-key $2 \
				-out $1.crt
	fi
fi
