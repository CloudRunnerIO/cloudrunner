import time

RESERVED = set(['names', 'from_value'])


def Enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)

    def reverse(v):
        return dict((value, key) for key, value in enums.iteritems())[v]

    def values():
        return [k for k in enums.keys() if k not in RESERVED]

    enums['from_value'] = staticmethod(reverse)
    enums['names'] = staticmethod(values)
    return type('Enum', (), enums)


def timestamp():
    return int(time.mktime(time.gmtime()))
