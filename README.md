# Garage Wi-Fi local approval

Independent local-approval service for the Garage-Guest hotspot.

It does not send SMS and does not share runtime state with `garage-sms-portal`.
Guests create a pending request; a staff member on the garage LAN signs in to the
approval panel and enters the corresponding TechnoVector order number or vehicle
plate. Only after that action does the service create its own `local-auth` HotSpot
binding and `local-auth-*` speed queue.

## Safety properties

- The container starts without any guest-facing HotSpot integration.
- The approval panel is protected by HTTP Basic Auth and an administrator CIDR.
- Requests expire without granting access after ten minutes by default.
- SMS bindings and queues (`sms-auth`) are never read, deleted, or changed.
- Logs contain request ID, IP, MAC, order reference, operator and timestamps. Do
  not copy customer names, telephone numbers, VINs or vehicle history into this
  service.

## Required environment

`GARAGE_ROUTER_PASSWORD` and `ADMIN_PASSWORD` must be set before the service can
approve a request. The router API user should be dedicated to this container and
restricted to its container IP.

The service is intentionally not deployed by this repository. Deployment is a
separate, reversible garage-router step after the image and health endpoint have
been tested.
