#!/bin/sh
# Give the jenkins user access to the mounted Docker socket, then start Jenkins as jenkins.
set -e
SOCK=/var/run/docker.sock
if [ -S "$SOCK" ]; then
  GID=$(stat -c %g "$SOCK")
  if [ "$GID" = "0" ]; then
    chmod 666 "$SOCK"   # local demo only
  else
    getent group "$GID" >/dev/null || groupadd -g "$GID" docker-host
    usermod -aG "$(getent group "$GID" | cut -d: -f1)" jenkins
  fi
fi
chown -R jenkins:jenkins /var/jenkins_home
exec gosu jenkins /usr/bin/tini -- /usr/local/bin/jenkins.sh "$@"
