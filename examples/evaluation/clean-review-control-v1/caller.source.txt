from .auth import may_read

def read_document(user, document):
    if not may_read(user, document):
        raise PermissionError("document access denied")
    return document.contents
