# Garage Wi-Fi approval portal

ARMv5 portal for the Garage-Guest hotspot. A guest can either create a request for
a staff member or verify a one-time SMS code. Both paths use the same `local-auth`
HotSpot binding, speed queue, firewall permission and expiry cleanup.

## Safety properties

- The container starts without any guest-facing HotSpot integration.
- The approval panel is protected by HTTP Basic Auth and administrator CIDRs.
- Requests expire without granting access after ten minutes by default.
- SMS codes live only in memory, expire after five minutes, have five verification
  attempts, and are rate-limited per device, number and portal.
- SMS is sent directly to the local HiLink modem, avoiding an extra router hop.
- Logs contain technical IDs, IP, MAC, method and timestamps. Telephone numbers
  and codes are never written to the log.

## Required environment

`GARAGE_ROUTER_PASSWORD` and `ADMIN_PASSWORD` must be set before the service can
approve a request. The router API user should be dedicated to this container and
restricted to its container IP.

`ADMIN_CIDRS` is a comma-separated list of allowed administrator networks.
`ADMIN_CIDR` remains supported when a single network is sufficient.

For SMS, set `HILINK_URL=http://192.168.8.1`. The router firewall must allow only
the container IP to reach `192.168.8.1:80`; no guest network needs access to the
modem UI. The useful optional settings are `SMS_CODE_TTL_SECONDS` (default `300`),
`SMS_RETRY_DELAY_SECONDS` (default `120`), `SMS_MAX_PER_HOUR` (default `2`) and
`SMS_GLOBAL_MAX_PER_HOUR` (default `20`).

Deployment is a separate, reversible garage-router step after the image and health
endpoint have been tested.
