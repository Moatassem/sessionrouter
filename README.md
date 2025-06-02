# Session Router v1.6 - written from scratch in Golang

- Highly optimized, high performance, modular, carrier-grade B2BUA with capacity **exceeding 2500 CAPS** and **1.5 Million concurrent sessions**
- Full SIP Headers and Body Manipulation with Stateful HMRs
- Docker-containerized compiled with golang:alpine

## Launching the build

Construction is automatic via Git CI/CD pipeline

## Service Details

Notes below ports are exposed **by default**:

- UDP 5060 for SIP
- TCP 8080 for HTTP Web API/Prometheus integration

## Routing Logic

- SR Go receives SIP REGISTER from IP/Soft SIP Phones, populates its internal in-memory Address of Records (AoR) DB (extremely fast lookups)
- SR Go routes calls to registered/reachable IP Phones based on R-URI, if not, it will route to Application Server (AS) socket passed during startup
- SR Go routes calls to AS if 'From' header is an existing IP Phone number/extension irrespective of the called number in R-URI (to avoid bypassing AS)

## Environment Variables

Environment variables must be defined in order to launch SR container.

-e as_sip_udp="#.#.#.#:####" (omit to enable internal Routing Engine & use rdb.json)

-e server_ipv4="#.#.#.#:####"

-e sip_udp_port="5060" (optional)

-e http_port="8080" (optional)

-e ka_interval="60" (optional)

-e proxy_udp_server="#.#.#.#:####" (optional - proxy mode)

-e auto_server_ipv4 ="" (optional - auto IPv4 server discover)

-e indialogue_interval="xxx" (optional - sipp testing mode)

## Special Headers

- P-Add-BodyPart -> add custom body parts to egress INVITE, in addition to the received INVITE body
  ex. P-Add-BodyPart: pidflo, indata

- pidflo: inserts PIDFLO XML location data used for ESN
- indata: inserts proprietary call transfer data

## Author

- **Moatassem TALAAT** - _Complete implementation_ -
