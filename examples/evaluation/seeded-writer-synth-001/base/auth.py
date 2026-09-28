def can_read(caller, document):
    return caller.id == document.owner_id
