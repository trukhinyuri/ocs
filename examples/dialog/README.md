# One fact shared by two participants

Participant B owns one ephemeral random value in the memory of its own process. Participant A asks for it through the native `agent.exchange` operation. B asks a clarifying question when a resource is missing. After receiving the scoped answer, A sends it back for confirmation. The test exchanges JSON-RPC frames over standard input and output, preserves message and context IDs, and consumes a finite turn and content-byte budget.

An identical delivery receives the saved answer. Reusing its message ID for another request fails. A claimed sender label cannot unlock a second resource. A new process has a different ephemeral session and its own fact. No generation service or credentials are involved. The [dialogue cases](../../conformance/test_agents.py) observe the conversation from A, through the public wire boundary.

The fixture accepts one text part, an optional context and a bounded budget. More modalities, durable conversation, a shared external cost ledger and streaming each require their own negotiated evidence. The [agent profile](../../spec/profiles/agents.md) defines that extension path.
