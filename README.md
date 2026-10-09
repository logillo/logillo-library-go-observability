# logillo-library-go-observability

The observability layer every Logillo Go service runs on. One module, one
package — `obs` — imported by service-api, every carrier adapter and the
accounting sync, so logging, tracing and the capture of what each service
exchanges with the outside behave the same everywhere and change in one place.

```go
import "github.com/logillo/logillo-library-go-observability/obs"
```

## What it does

**Logging.** `InitLogging` installs the process-wide `slog` logger: Cloud
Logging JSON on Cloud Run, readable text locally. Every record written with a
request context carries the request id, the active trace, and whatever keys
the service bound with `ContextWithAttrs` — the acting user, the company, the
shipment a request works on.

**Tracing.** `InitTracing` installs OpenTelemetry with W3C propagation,
exporting to Cloud Trace on GCP. `HTTPHandler` opens the server span;
`NewHTTPClient` carries the trace onward, so one request is one waterfall from
the portal through service-api and an adapter to the carrier.

**One request id.** `RequestIDMiddleware` accepts or mints `X-Request-ID` and
echoes it; service-api forwards it to every adapter; every log line in every
service carries it.

**Capture.** A `Capturer` records HTTP exchanges in full — request and
response, headers and bodies — as `exchange` log records:

```go
capturer := obs.NewCapturer("carrier-a", obs.ArchiveTo(archive))

// outbound: every call this client makes is captured
client := capturer.Client(30 * time.Second)

// per call: name it, archive it, or capture it only when the answer changes
ctx = obs.WithOperation(ctx, "booking.create")
ctx = obs.WithArchiving(ctx)
ctx = obs.WithChangeKey(ctx, "tracking:"+trackingNumber)

// inbound: the service decides what to keep once the response is written
router.Use(capturer.Inbound(func(r *http.Request, status int) obs.InboundDecision {
    apiKey := obs.ActorAPIKeyID(r.Context()) != ""
    write := r.Method != http.MethodGet
    return obs.InboundDecision{Log: apiKey || write, Archive: apiKey && write}
}))
```

Every capture obeys the same rules, tested here once for all services:

- **Secrets are blanked** by name — headers, query parameters, JSON fields,
  form fields, XML elements, all by the one list. Any name containing
  `password`, `secret`, `token`, `credential`, `apikey`, `authorization`,
  `signature`, `cookie`, `accountnumber`, `client_id`, `idempotency`, the
  exact names `pass`, `pwd`, `session`, `eid`, or whose last word is `key`
  (`customerKey`, `X-Api-Key`), except identifiers such as `primaryKey`.
- **Files become a size and a SHA-256** — labels, PDFs, images, any base64
  content — so what was exchanged can still be proven without the bytes.
- **Large bodies are cut** at 100 KiB and marked `truncated`.
- **Repeated answers are captured once per change** when the call carries a
  change key: a tracking poll writes its bodies when the status moves and a
  bodiless DEBUG line otherwise.
- Every record carries `capture: "exchange"` — the field the log router uses
  to file these records in their own bucket, with their own retention and
  readers.

**Archive.** Exchanges marked with `WithArchiving` are also stored as files
in a Cloud Storage bucket (`EXCHANGE_ARCHIVE_BUCKET`, see
`NewArchiveFromEnv`), one JSON file per exchange under
`<peer>/<day>/<request id>/<time>-<operation>-<hash>.json`, holding exactly
what the log holds. Logs answer questions for weeks; the archive answers them for as
long as a dispute can arise.

## What it does not do

It knows no business. Which keys a service binds to its log lines — a
shipment reference, an order id — is the service's choice; the library only
carries them. The convention is `<thing>Id` for identifiers and
`<thing>Reference` for human-readable references.

## Development

```
go test ./...
```

Consumers pin a tagged version. A rule that changes here — a new secret
field name, a new file type — reaches every service with a version bump.
