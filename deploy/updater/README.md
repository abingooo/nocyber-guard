# Restricted update agent

The admin UI never receives the Docker socket. A small host service exposes only three operations over a Unix socket: status, update to a validated official release tag, and rollback to the previous pinned digest.

Install the matching `nocyber-updater-linux-amd64` or `nocyber-updater-linux-arm64` release asset as `/usr/local/bin/nocyber-updater`, copy the example environment file to `/etc/nocyber-updater.env`, and install the systemd unit. Start the agent before adding `docker-compose.updater.yml` to the Guard compose command because Docker must bind an existing Unix socket.

The compose override mounts the runtime directory read-only instead of binding a single socket inode, so an agent restart can safely recreate the socket without stranding the container on a stale inode. The agent accepts only `ghcr.io/abingooo/nocyber-guard@sha256:...` after pulling an official version tag. It atomically updates `NCG_IMAGE`, recreates only the Guard service, waits for the configured health endpoint, and automatically restores the prior image when the health check fails.
