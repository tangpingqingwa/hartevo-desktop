# AWS Lambda invocation-result Layer 1 contract

This directory defines the standalone Layer 1 contract for bounded AWS
Lambda invocation evidence. The implementation lives in the nested workspace
at `hartevo-rs/aws-lambda-invocation-result-plugin` and owns only typed scope,
recording/fake/loopback/BLOCKED_ENV provider projections, proposal compilation,
digest fencing, and reversible registration metadata.

The contract is scoped to the `deployment_verification` objective type; the
Mission, Project, and Work Product revisions remain part of the exact fence.

The scope binds the exact AWS account, region, unqualified function ARN,
published version, optional alias, code SHA-256, invocation type, input
revision and digest, invocation configuration, retry policy, Hartevo Mission,
Project, and Work Product revisions. Request/response bodies, logs, and
credential material are never retained. Synchronous payloads are bounded to
6 MiB and asynchronous event payloads to 1 MiB, matching the documented
Lambda `Invoke` limits.

Layer 1 never resolves a SigV4 credential, performs live `Invoke` or
`GetFunction` HTTPS traffic, deploys code, mutates configuration, changes IAM,
configures event-source mappings, creates a durable provider receipt, reads
back independently, adopts an Outcome, or claims Connected/native/
first-party evidence. Recording, fake, loopback, and `BLOCKED_ENV` evidence
always remains non-connected, non-native, and non-first-party.

Official references:

- [AWS Lambda Invoke API](https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html)
- [AWS Lambda GetFunction API](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html)
- [Understanding Lambda function invocation methods](https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html)

Native SigV4 resolution, live HTTPS invocation and metadata reads, durable
receipts, independent output/readback reconciliation, and verified Mission
Work Product adoption remain Layer 2 gaps. Step Functions #305 owns workflow
orchestration; Modal #372 owns managed FunctionCall; Cloud Run #369 owns
container deployment; Bedrock #326 owns model inference.
