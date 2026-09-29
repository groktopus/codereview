# Document access contract

A caller may read a document only when the caller owns that document. Cross-owner access must be denied. The service checks `may_read` before returning document contents.
