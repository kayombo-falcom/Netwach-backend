#!/bin/sh
set -e

attempt=0
max_attempts=30

until python manage.py migrate --noinput; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "Database did not become ready after $max_attempts attempts. Exiting."
    exit 1
  fi
  echo "Database not ready yet (attempt $attempt/$max_attempts). Retrying in 2s..."
  sleep 2
done

exec "$@"
