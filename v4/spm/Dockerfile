ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openssl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 doofusai \
 && useradd --uid 10001 --gid 10001 --no-create-home doofusai \
 && install -o 10001 -g 10001 -d /data
WORKDIR /opt/doofusai
COPY *.py ./
COPY web ./web
COPY deploy/container-start.sh ./container-start.sh
RUN chmod 0555 ./container-start.sh
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8000
ENTRYPOINT ["/opt/doofusai/container-start.sh"]
