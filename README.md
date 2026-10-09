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

**One request id.** `RequestIDMiddleware` keeps the `X-Request-ID` a caller
sends when it is a UUID, mints a UUIDv7 otherwise, and echoes it; a capturer
built with `ForwardRequestID()` sends it on to another Logillo service; every
log line in every service carries it.

**Capture.** A `Capturer` records HTTP exchanges in full — request and
response, headers and bodies — as `exchange` log records:

```go
capturer := obs.NewCapturer("carrier-a",
    obs.ArchiveTo(archive),
    // what no generic rule can know: this peer's account number travels as a party's id
    obs.SensitiveFields(func(parent, name string) bool { return parent == "parties" && name == "id" }),
    // what changes on every answer without meaning a change
    obs.VolatileFields("transactionId"),
)

// outbound: every call this client makes is captured (a zero timeout is none)
client := capturer.Client(30 * time.Second)

// per call: name it, archive it, or capture it only when the answer changes
ctx = obs.WithOperation(ctx, "booking.create")
ctx = obs.WithArchiving(ctx)
ctx = obs.WithChangeKey(ctx, "tracking:"+trackingNumber)

// inbound: mounted on the router, inside the access log, so the matched route
// is known; the service decides what to keep once the response is written
router.Use(capturer.Inbound(func(r *http.Request, status int) obs.InboundDecision {
    apiKey := obs.ActorAPIKeyID(r.Context()) != ""
    write := r.Method != http.MethodGet
    return obs.InboundDecision{Log: apiKey || write, Archive: apiKey && write}
}))
```

Every capture obeys the same rules, tested here once for all services:

- **Secrets are blanked** by name — headers, query parameters, URLs carried
  as values or in `Location`, JSON fields, form fields, XML elements and
  CDATA, documents encoded inside strings, `name: value` lines in text — all
  by one test (`redact.go`): a name containing `password`, `secret`, `token`,
  `credential`, `apikey`, `authorization`, `hmac`, `cookie`, an account
  number under any spelling, `client_id`, `idempotency`; a request
  `signature`; the exact names `pass`, `pwd`, `pin`, `otp`, `session`,
  `eid`, `sig`, `auth`, `account`, `apiid`; a name ending in `key`
  (`customerKey`, `X-Api-Key`). Identifiers stay: a bare `key`, `clientId`,
  `signatureRequired`, `nextPageToken`. A peer's own shape is added with
  `SensitiveFields`.
- **Files become a size and a SHA-256** — labels, PDFs, images, any base64
  content, a PDF handed over as text — so what was exchanged can still be
  proven without the bytes.
- **Bodies are held up to 2 MiB** for the record; the log line carries them
  cut at 64 KiB and marked `truncated`, the archive whole. An inbound body
  is read as the handler reads it, never ahead of it.
- **Repeated answers are captured once per change** when the call carries a
  change key: a tracking poll writes its bodies when the status moves and a
  bodiless DEBUG line otherwise — a failure stays a WARNING either way. Fields
  named with `VolatileFields` are left out of the comparison.
- **Traces carry no secrets either**: the URL attributes of exported spans
  are blanked the same way, and `ErrorText` gives an error's text with its
  URL's secrets blanked.
- Every record carries `capture: "exchange"` — the field the log router uses
  to file these records in their own bucket, with their own retention and
  readers.

**Archive.** Exchanges marked with `WithArchiving` or approved by
`ArchiveWhen` are also stored as files in a Cloud Storage bucket
(`EXCHANGE_ARCHIVE_BUCKET`, see `NewArchiveFromEnv`), one JSON file per
exchange under `<peer>/<day>/<request id>/<time>-<operation>-<hash>.json`,
with the bodies whole. The write runs on a context of its own, so a client
that stopped waiting costs no record. Logs answer questions for weeks; the
archive answers them for as long as a dispute can arise.

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
