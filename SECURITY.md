# Security

The trust boundary includes package admission, permission checks, identity, egress, data retention and externally visible effects. See [composition](spec/composition.md) and [effects](spec/profiles/effects-and-jobs.md).

The reference programs are developer fixtures for reviewed local code and isolated loopback tests. They are not a general-purpose process sandbox or a production authentication service. For hostile packages or remote deployments, enforce the negotiated isolation and transport policy before activation.

Report a suspected issue privately to the repository owner through a previously established private contact. Include the affected version, role, boundary and synthetic reproducer. Keep credentials, personal data and operational endpoints out of public issues. Publication of advisories and fixes is coordinated by the maintainer.
