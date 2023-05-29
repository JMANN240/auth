#!/bin/bash

# Generate the private key if it doesn't exist
if [ ! -f private.pem ]; then
	openssl genrsa -out private.pem 2048;
fi

# Generate the public key if it doesn't exist
if [ ! -f public.pem ]; then
	openssl rsa -in private.pem -pubout -outform PEM -out public.pem;
fi