# Status reader

The manifest declares a single read operation. The reference policy grants only resource `demo`. The executor has no upstream network access requirement and stores no state. Run it with either development host as described in [the quickstart](../../docs/quickstart.md).

A successful answer identifies the resource and returns a known state. An ungranted resource is denied. A malformed resource ID is an input error. The fixture is intentionally deterministic. It makes no live availability claim about a real service.
