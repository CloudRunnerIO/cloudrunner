import psutil as _psutil


class psutil(object):

    def __init__(self):
        pass

    @classmethod
    def virtual_memory(cls):
        return _psutil.virtual_memory()

    @classmethod
    def cpu_count(cls, logical=True):
        try:
            # psutil 2.0
            return _psutil.cpu_count(logical=logical)
        except:
            if not logical:
                return 'N/A'
            return _psutil.NUM_CPUS

    @classmethod
    def cpu_percent(cls):
        return _psutil.cpu_percent()

    @classmethod
    def cpu_times_percent(cls):
        return _psutil.cpu_times_percent()
