![SRGo](./webserver/sipgopher.png)

# Session Router v1.7.2 - written from scratch in Golang

- Highly optimized, high performance, modular, carrier-grade B2BUA with capacity **exceeding 2500 CAPS** and **1.5 Million concurrent sessions**
- Full SIP Headers and Body Manipulation with Stateful HMRs
- Docker-containerized image compiled with golang:alpine

## Launching the build

- Building and launching the software using existing Dockerfile

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

-e auto_server_ipv4 ="" (optional - auto server IPv4 discovery)

-e indialogue_interval="xxx" (optional - sipp testing mode)

## Local Routing DB

Use "rdb.json" file to setup internal Routing DB. Example below.

```json
[
  {
    "userpartPattern": "^777(8157\\d+)",
    "routingRecord": {
      "noAnswerTimeout": -1,
      "no18xTimeout": 7,
      "maxCallDuration": -1,
      "outRuriUserpart": "+2385801$1",
      "outRuriHostport": "",
      "outCallFlow": "TransformEarlyToFinal",
      "disallowSimilar18x": false,
      "disallowDifferent18x": false,
      "steerMedia": false
    }
  },
  {
    "userpartPattern": "^(12355)$",
    "routingRecord": {
      "noAnswerTimeout": -1,
      "no18xTimeout": 7,
      "maxCallDuration": -1,
      "outRuriUserpart": "$1",
      "outRuriHostport": "192.168.1.2:5098",
      "outCallFlow": "Transparent",
      "disallowSimilar18x": false,
      "disallowDifferent18x": false,
      "steerMedia": false
    }
  },
  {
    "userpartPattern": "^(12389)$",
    "routingRecord": {
      "noAnswerTimeout": -1,
      "no18xTimeout": 7,
      "maxCallDuration": -1,
      "outRuriUserpart": "$1",
      "outRuriHostport": "192.168.1.2:5099",
      "outCallFlow": "TransformEarlyToFinal",
      "disallowSimilar18x": false,
      "disallowDifferent18x": false,
      "steerMedia": false
    }
  },
  {
    "userpartPattern": "^(99999)$",
    "routingRecord": {
      "noAnswerTimeout": -1,
      "no18xTimeout": -1,
      "maxCallDuration": 60,
      "outRuriUserpart": "",
      "outRuriHostport": "",
      "outCallFlow": "EchoResponder",
      "disallowSimilar18x": false,
      "disallowDifferent18x": false,
      "steerMedia": false
    }
  },
  {
    "userpartPattern": "\\d+",
    "routingRecord": {
      "noAnswerTimeout": 60,
      "no18xTimeout": 4,
      "maxCallDuration": -1,
      "outRuriUserpart": "12388",
      "outRuriHostport": "somewhere:5097",
      "outCallFlow": "Transparent",
      "disallowSimilar18x": true,
      "disallowDifferent18x": false,
      "steerMedia": true
    }
  }
]
```

## Existing API calls:

- `GET /api/v1/stats`
  Get general stats of session router server
- `GET /api/v1/phone`
  Get server in-memory endpoint Phones
- `GET /api/v1/session`
  Get server in-memory SIP sessions
- `GET /api/v1/config`
  Get server in-memory Routing DB
- `PATCH /api/v1/config`
  Refresh server in-memory Routing DB from the local rdb.json file
- `GET /metrics`
  Get server Prometheus scraping & observability
- `GET /`
  Get server test webpage

## Special Headers

- P-Add-BodyPart -> add custom body parts to egress INVITE, in addition to the received INVITE body
  ex. P-Add-BodyPart: pidflo, indata

- pidflo: inserts PIDFLO XML location data used for ESN
- indata: inserts proprietary call transfer data

## Author

- **Moatassem TALAAT** - _Complete implementation_ -
