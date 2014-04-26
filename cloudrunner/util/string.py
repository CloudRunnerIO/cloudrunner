import json


def stringify(*values):
    for value in values:
        if value is None:
            yield value
        if isinstance(value, unicode):
            yield value.encode('utf8')
        else:
            yield str(value)


def jsonify(*values):
    for value in values:
        if value is None:
            yield ''
        if isinstance(value, unicode):
            yield value.encode('utf8')
        else:
            yield json.dumps(value)


def stringify1(value):
    if value is None:
        return value
    if isinstance(value, unicode):
        return value.encode('utf8')
    else:
        return str(value)


def jsonify1(value):
    if value is None:
        return ''
    if isinstance(value, unicode):
        return value.encode('utf8')
    else:
        return json.dumps(value)
