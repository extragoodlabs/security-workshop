FROM postgres:15.3-alpine

ENV POSTGRES_DB bank
COPY postgres-data.sql /docker-entrypoint-initdb.d/
COPY entrypoint.sh /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
