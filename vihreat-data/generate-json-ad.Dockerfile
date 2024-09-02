FROM python:3.10-alpine
COPY ./vihreat-data /vihreat-data
VOLUME /json-ad
WORKDIR /vihreat-data
ENTRYPOINT ["/bin/sh", "generate-json-ad.sh"]