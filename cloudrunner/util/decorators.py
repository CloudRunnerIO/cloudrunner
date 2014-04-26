import logging
from functools import wraps

LOG = logging.getLogger('wrapper')


def catch_ex(message=None, to_exit=True):
    def method_wrapper(f):
        @wraps(f)
        def wrapper(*args, **kwds):
            try:
                return f(*args, **kwds)
            except Exception, ex:
                if message:
                    m = message.format(f.__name__, ex)
                else:
                    m = "Error executing [%s]:%s" % (f.__name__, ex)
                LOG.error(m)
                if to_exit:
                    exit(1)
        return wrapper
    return method_wrapper
