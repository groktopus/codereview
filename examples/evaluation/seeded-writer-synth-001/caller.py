from auth import can_read


def get_document(caller, document):
    if not can_read(caller, document):
        raise PermissionError("document access denied")
    return document
