RESERVED = set(['names', 'from_value'])


def Enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = lambda v: dict((value, key)
                             for key, value in enums.iteritems())[v]
    values = lambda: [k for k in enums.keys() if k not in RESERVED]
    enums['from_value'] = staticmethod(reverse)
    enums['names'] = staticmethod(values)
    return type('Enum', (), enums)
