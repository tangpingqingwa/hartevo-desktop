# BambooHR employee directory result — Layer 1

This standalone contract defines a bounded, read-only BambooHR employee-directory
projection below Hartevo Truth, Consent, Effect, Receipt, Verification,
Outcome, identity, access-grant, and Work Product authority.

The provider models `GET /api/v1/employees/directory` with JSON acceptance and
the `employee_directory` OAuth permission. BambooHR returns a company-configured
`fields` array and matching employee records in one response; Layer 1 retains
only field/employee/value digests, counts, bounded response metadata, and
redacted request/cost receipts. It also exposes a separate bounded
`GET /api/v1/employees` metadata seam with an allowlisted field selection
(`jobTitleName`, `department`, `division`, `location`, `supervisor`, `status`),
opaque cursor pagination, and a stable change-fence digest across pages.

Work Product, Project, Mission, Consent, permission, fieldset, employee-field
selection, provider revision, and registration digests are all part of the
scope/evidence fence. The projection never retains the company subdomain,
employee IDs, names, email, phone values, addresses, compensation, sensitive
fields, raw field values, XML/JSON payload, credential material, cursor tokens,
or raw provider diagnostics.

Fixture, recording, loopback, and `BLOCKED_ENV` transports are provenance modes,
not live connections. All are permanently `connected=false`, `native=false`,
and `first_party=false`; they do not produce a durable first-party provider
receipt. A proposal is review-only and cannot be adopted as kernel Truth,
Consent, identity, access, Effect, Receipt, Verification, Outcome, or Work
Product authority.

## Layer-2 gaps

Native Basic/OAuth resolution and live BambooHR HTTPS, durable provider receipts,
independent rereads, production retry scheduling, directory synchronization,
employee mutation, raw directory export, consented effects, identity/access
grant authority, and verified Mission Work Product adoption remain Layer-2 host
responsibilities.
