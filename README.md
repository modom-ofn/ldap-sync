# ldap-sync (AuthPortal Companion)

[![Docker Pulls](https://img.shields.io/docker/pulls/modomofn/ldap-sync.svg)](https://hub.docker.com/r/modomofn/ldap-sync)
[![Docker Image Size](https://img.shields.io/docker/image-size/modomofn/ldap-sync/latest)](https://hub.docker.com/r/modomofn/ldap-sync)
[![Go Version](https://img.shields.io/badge/Go-1.25.3%2B-00ADD8?logo=go)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL3.0-green.svg)](https://github.com/modom-ofn/ldap-sync?tab=GPL-3.0-1-ov-file#readme)
[![Vibe Coded](https://img.shields.io/badge/Vibe_Coded-OpenAI_Codex-purple)](https://developers.openai.com/codex/windows)

**ldap-sync** is the lightweight bridge that keeps your directory in lockstep with [AuthPortal](https://github.com/modom-ofn/auth-portal). It speaks Postgres on one side and LDAP on the other, exporting only the users that AuthPortal has approved for downstream apps.

> [!NOTE]
> Before diving in, make sure AuthPortal is up and humming. ldap-sync simply mirrors its source of truth.

> [!IMPORTANT]
> **Use at your own risk.** This project leans on Vibe Coding practices - AI pair-programming, automated refactors, and rapid iteration. Treat releases as starting points - test, monitor, and adapt to your stack. AuthPortal and ldap-sync remains an independent effort with no endorsement from Plex, Emby, or Jellyfin.

> [!NOTE]
> - Docker Hub: https://hub.docker.com/r/modomofn/ldap-sync
> - GitHub Repo: https://github.com/modom-ofn/ldap-sync

---

## Why it exists

- **Downstream SSO without duct tape**  
  Sync AuthPortal's authorized media users into LDAP so legacy services (Grafana, Jenkins, whatever) can reuse the same access decisions.

- **Multi-provider aware**  
  Ships the full identities matrix (Plex, Jellyfin, Emby) right into LDAP `description` attributes for cross-reference. Works with every AuthPortal `v2.0.x` release, including the latest [v2.0.3](https://github.com/modom-ofn/auth-portal/releases/tag/v2.0.3).

- **Zero-click OU bootstrap**  
  Creates the target OU branch at startup if it is missing, so fresh installs do not require manual LDIF prep.

- **Container ready**  
  Single binary, stateless. Point at your Postgres + LDAP endpoints, mount env vars, and let it stream changes on schedule (cron, systemd, Kubernetes Job, you pick).

---

## How it works

1. **Connect** to the AuthPortal database using `DATABASE_URL` (defaults to the docker-compose setup).  
2. **Read** either the `identities` table (multi-provider era) or the legacy `users` table, trimming to rows with `media_access = TRUE`.  
3. **Bind** to LDAP via `LDAP_HOST` and `LDAP_ADMIN_DN`, optionally StartTLS.  
4. **Ensure** the base OU exists. ldap-sync will create `ou=users` under your domain component if needed.  
5. **Upsert** each entry as `inetOrgPerson`, writing email + provider metadata into LDAP attributes. Existing entries get patched; missing ones are added.

All operations run within sane timeouts and log progress in plain English so you can wire it into any orchestrator.

---

## Configuration snapshot

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `postgres://authportal:change-me@postgres:5432/authportaldb?sslmode=disable` | AuthPortal Postgres connection string |
| `LDAP_HOST` | `ldap://openldap:389` | Target LDAP endpoint (supports `ldaps://`) |
| `LDAP_ADMIN_DN` | `cn=admin,dc=authportal,dc=local` | Bind DN |
| `LDAP_ADMIN_PASSWORD` | *(empty)* | Bind credential |
| `BASE_DN` | `ou=users,dc=authportal,dc=local` | Where entries are stored/created |
| `LDAP_STARTTLS` | `false` | Enable StartTLS negotiation |

Add your own scheduler (cron, k8s job, GitHub Actions, etc.) to run the binary as often as you need.

---

## Getting Started

```bash
# build the container
docker build -t modomofn/ldap-sync:dev ./ldap-sync

# run against a local stack
docker run --rm \
  -e DATABASE_URL=postgres://authportal:change-me@postgres:5432/authportaldb?sslmode=disable \
  -e LDAP_HOST=ldap://openldap:389 \
  -e LDAP_ADMIN_DN="cn=admin,dc=authportal,dc=local" \
  -e LDAP_ADMIN_PASSWORD=supersecret \
  modomofn/ldap-sync:dev
```

When the run completes you will see logs for any adds/updates. Rerun anytime AuthPortal grants or revokes access.

---

## Need the portal itself?

ldap-sync is a supporting actor. The feature-rich headliner lives here: **[AuthPortal on GitHub](https://github.com/modom-ofn/auth-portal)**. Start there to bootstrap your auth stack, then drop ldap-sync in to keep everything else in sync.

---

> [!IMPORTANT]
> **Use at your own risk.** This project leans on Vibe Coding practices - AI pair-programming, automated refactors, and rapid iteration. Treat releases as starting points - test, monitor, and adapt to your stack. AuthPortal and ldap-sync remains an independent effort with no endorsement from Plex, Emby, or Jellyfin.