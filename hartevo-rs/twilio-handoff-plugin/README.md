# Twilio Handoff Plugin — Layer 1

This independently testable crate owns the typed Twilio SMS/WhatsApp Mission
handoff boundary for EXT-TWILIO-01.

Layer 1 produces a canonical, non-mutating handoff proposal and a redacted
receipt/status projection. The fixture and loopback providers are explicitly
not connected, and `BLOCKED_ENV` never reports native or Connected evidence.
The HTTPS transport is a read-only seam for a future native implementation;
there is no live create-message call, webhook listener, or unverified callback
adoption in this layer.

Native gaps are deliberate: credentials, unsupported channels, scope
mismatch, 429, timeout, and ambiguous responses remain non-Connected outcomes.
A later Layer 2 must add environment-gated native transport, readback, and
verified callback ingress before any external message or Mission adoption can
occur.
