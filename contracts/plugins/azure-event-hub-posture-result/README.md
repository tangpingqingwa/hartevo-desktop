# Azure Event Hub posture result

This directory freezes the standalone Layer-1 contract for the governed Azure
Event Hub posture result capability. The capability reads only bounded Azure
Resource Manager metadata for one exact tenant, subscription, resource group,
namespace, event hub, and consumer group. It does not read event data, use
AMQP, claim checkpoint or lag truth, mutate Event Hubs, or adopt a Mission
Outcome or Work Product.

The primary API basis is:

- [Namespaces - Get](https://learn.microsoft.com/en-us/rest/api/eventhub/namespaces/get?view=rest-eventhub-2024-01-01)
- [Event Hubs - Get](https://learn.microsoft.com/en-us/rest/api/eventhub/event-hubs/get?view=rest-eventhub-2024-01-01)
- [Consumer Groups - Get](https://learn.microsoft.com/en-us/rest/api/eventhub/consumer-groups/get?view=rest-eventhub-2024-01-01)
- [Consumer Groups - List By Event Hub](https://learn.microsoft.com/en-us/rest/api/eventhub/consumer-groups/list-by-event-hub?view=rest-eventhub-2024-01-01)

The nested Rust crate is intentionally a standalone root. Recording, fixture,
fake, loopback, and `BLOCKED_ENV` transports always report
`connected=false`, `native=false`, and `first_party=false`; they never produce
a durable provider receipt.
