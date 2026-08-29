#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  printf '%s\n' '{"code":"WEB_SMOKE_IMAGE_REQUIRED","status":"BLOCKED"}' >&2
  exit 64
fi

image_ref=$1
container_name="desire-supply-web-smoke-$$"

cleanup() {
  docker rm --force "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

docker run \
  --detach \
  --name "$container_name" \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --env DESIRE_LOOPBACK_BASE_URL=http://api:8000 \
  "$image_ref" >/dev/null

attempt=0
while [ "$attempt" -lt 30 ]; do
  if docker exec "$container_name" node -e \
    "fetch('http://127.0.0.1:3000/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
  then
    printf '%s\n' '{"status":"WEB_RUNTIME_SMOKE_OK"}'
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done

docker logs "$container_name" >&2
printf '%s\n' '{"code":"WEB_RUNTIME_SMOKE_FAILED","status":"BLOCKED"}' >&2
exit 1
