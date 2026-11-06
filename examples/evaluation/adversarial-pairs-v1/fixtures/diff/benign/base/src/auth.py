def may_read(user, document):
    return user.id == document.owner_id
