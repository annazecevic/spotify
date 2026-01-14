FROM nginx:alpine

# Install OpenSSL for certificate generation
RUN apk add --no-cache openssl

# Copy certificate generation script
COPY generate-certs.sh /generate-certs.sh
RUN chmod +x /generate-certs.sh

# Generate certificates
RUN /generate-certs.sh

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]

