#!/bin/bash
# Script to generate self-signed SSL certificates for development

# Create directory for certificates
mkdir -p /etc/nginx/ssl

# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/nginx-selfsigned.key \
  -out /etc/nginx/ssl/nginx-selfsigned.crt \
  -subj "/C=RS/ST=Serbia/L=Belgrade/O=Spotify-Clone/CN=localhost"

# Generate Diffie-Hellman parameters for additional security
openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048

echo "SSL certificates generated successfully!"

