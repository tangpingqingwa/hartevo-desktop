# Hartevo Desktop

Status: **Current**

## Register

product

## Users

Hartevo Desktop serves founders, growth teams, agencies, cross-border operators, and creator or affiliate teams that need one durable work entrance for market research, channel operations, CRM, email, creator discovery, outreach, distribution, and conversion. They think in business goals and constraints, not modules, and expect to direct the system in natural language while retaining control over approvals, data, and external actions.

## Product Purpose

Hartevo is an agent-native growth operating system. A user owns multiple promotional projects; each project owns its Missions, Truth Graph, memory, files, connection scopes, consent, approval policies, work products, and execution receipts. Hartevo continuously coordinates tasks through one project-level dispatcher and makes specialist work surfaces share the same Mission state. Success means the user can state an outcome once, let Hartevo research and prepare work across channels, and intervene only where judgment, authorization, or new context is needed.

Desktop is local-first. A project can live in an existing local folder, a newly created local folder, a cloud workspace, or a local workspace with optional encrypted synchronization. Cloud storage is never implied by project creation. Credentials live in the operating-system vault; external writes remain governed by explicit scopes and approval policy.

## Brand Personality

Calm, expert, precise, and quietly capable. The product should feel like a mature desktop operating environment: dense enough for real work, restrained enough to preserve focus, and honest about uncertainty, permission, and provider state. Chinese and English product language should be concise and operational rather than theatrical.

## Anti-references

Avoid generic AI chat shells, cloud-only assumptions, decorative AI gradients, nested card dashboards, oversized marketing typography, and navigation that forces users to learn which module owns a request. Avoid fragmented conversations, one-shot task framing, fake integrations, fabricated certainty, and hidden side effects. Do not overload account menus with capability catalogs; project work, system settings, account identity, and connection authorization have separate homes.

## Design Principles

1. Keep one persistent natural-language command relationship with the project dispatcher; work surfaces are synchronized views, not separate agents.
2. Make tasks and Missions the primary work objects while preserving the user → project → task hierarchy.
3. Put the next useful action beside the evidence or state that justifies it.
4. Show local path, storage mode, synchronization, permission scope, consent, and execution status explicitly.
5. Make external effects inspectable and reversible where possible; never infer approval from connection or login.
6. Use Hartevo's forest green, warm gold, graphite, quiet borders, compact typography, and restrained motion consistently.

## Engineering Mandate

When Hartevo encounters a difficult technical or product barrier, the team must not mistake inherited assumptions, upstream implementation choices, current framework limits, or conventional patterns for fundamental constraints. Return to first principles: restate the user outcome, domain invariants, authority boundary, observable failure and physical or protocol limits; then derive the smallest architecture that can satisfy them. The team is authorized to replace abstractions, redesign subsystem boundaries, build a new Rust mechanism, or propose a genuinely novel architecture when evidence shows that the current path cannot meet the product contract.

“Do not be constrained” does not authorize bypassing user consent, security, privacy, licensing, source provenance, deterministic state, or Eval gates. An architectural innovation is complete only when it has a reproducible experiment, an explicit decision record, migration and rollback paths, and permanent tests or Mission fixtures. Difficulty is a reason to reason more deeply, not to silently narrow the product promise or accumulate an opaque workaround.

## Accessibility & Inclusion

Target WCAG 2.2 AA. Preserve keyboard operation, visible focus, semantic labels and live states, sufficient contrast, reduced-motion support, and usable layouts at desktop and narrow laptop widths. Never rely on color alone for state. Support Chinese and English content, long paths, long project names, screen magnification, and offline operation without losing access to local projects.
