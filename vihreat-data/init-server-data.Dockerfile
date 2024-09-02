FROM joepmeneer/atomic-server:master
COPY ./vihreat-data/init-server-data.sh /app/init-server-data.sh
VOLUME /json-ad
VOLUME /atomic-storage
WORKDIR /app
ENTRYPOINT ["/bin/sh", "/app/init-server-data.sh"]