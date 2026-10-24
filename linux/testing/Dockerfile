# Throwaway target with a real OpenSSH server for testing/test-scripts.sh and
# testing/test-ssh.sh. Build it once (needs the network):
#   docker build -t ccdc-test:debian testing/
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/*
