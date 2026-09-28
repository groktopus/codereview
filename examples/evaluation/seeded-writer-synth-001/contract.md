# Document access contract

A caller may read a document only when the caller's ID matches the document's owner ID.
The `can_read` function is the authorization boundary used by the caller.
