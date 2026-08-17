# AWS Service Quotas result contract

This directory contains the versioned Layer-1 contract for the governed AWS
Service Quotas posture result slice (`EXT-AWS-SERVICE-QUOTA-01`). The contract
allows only bounded reads of applied/default quota posture and request-history
states for an exact account/region/service/quota scope.

Quota identity, values, unit, adjustable/global flags, usage-metric metadata,
and bounded request-history states cross the boundary as digests only. Raw
usage series, requester/support-case material, provider payloads, credentials,
and pagination tokens are not retained or serialised.

The fixture, recording, loopback, and `BLOCKED_ENV` seams are deliberately
non-native and non-connected. Quota increases, quota-template/support-case
mutation, utilization-report side effects, autoscaling, financial or
infrastructure guarantees, kernel authority, and native Connected claims are
Layer-2 gaps.
