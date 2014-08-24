def Enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = lambda v: dict((value, key)
                             for key, value in enums.iteritems())[v]
    enums['from_value'] = staticmethod(reverse)
    return type('Enum', (), enums)
