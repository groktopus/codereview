# Document access contract

A caller may read a document only when the caller owns it. Cross-owner
access must be denied; `may_read` enforces the owner check.
