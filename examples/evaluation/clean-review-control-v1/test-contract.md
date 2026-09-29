# Authored access test contract (fixture data; not executed)

- An owner can read their own document.
- A different user cannot read the document; the service raises `PermissionError` and does not return its contents.
