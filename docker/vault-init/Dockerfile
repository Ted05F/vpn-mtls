FROM hashicorp/vault:1.16
RUN apk add --no-cache python3 bash curl
COPY init.sh /init.sh
RUN chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
