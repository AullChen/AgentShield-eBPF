# Dashboard Overview API

Day 42 replaces the Overview mock with `GET /api/v1/overview`. The endpoint
requires the same class of read-only Bearer credential as the realtime stream,
sets `Cache-Control: no-store`, and returns current Run summaries, event/policy/
block counts, and reported capability states.

All counters cross the JSON boundary as decimal strings. The dashboard validates
the response and formats them with `BigInt`; it never first converts them to a
JavaScript `number`.

Set these only in the Next.js server environment:

```sh
AGENTSHIELD_API_URL=http://127.0.0.1:8080
AGENTSHIELD_READ_TOKEN=replace-with-a-random-read-only-token
```

Non-loopback control-plane URLs must use HTTPS. The token is used by the server
component and is not emitted into the browser bundle. Missing configuration,
authentication failure, an incompatible schema, and an unavailable API render
an explicit unavailable state rather than fabricated metrics.

`OverviewState` is the tested in-memory provider contract. Production audit,
policy, Run lifecycle, and diagnostic fan-in plus listener composition remain
pending; the UI/API data path is source-complete but not presented as a running
deployment.
