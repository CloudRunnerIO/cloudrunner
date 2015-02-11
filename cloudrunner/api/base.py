from copy import copy
import json
import logging
import requests

from exceptions import *  # noqa

logging.basicConfig()
LOG = logging.getLogger("ApiClient")
LOG.setLevel(logging.INFO)


class ApiObject(object):

    @classmethod
    def _apify(cls, **kwargs):
        return ApiObject(**kwargs)

    def __init__(self, **kwargs):
        self._values = kwargs
        for k, v in kwargs.items():
            if isinstance(v, dict):
                setattr(self, k, self._apify(**v))
            elif isinstance(v, (list, set, tuple)):
                arr = []
                for i in v:
                    if isinstance(i, dict):
                        arr.append(self._apify(**i))
                    else:
                        arr.append(i)
                setattr(self, k, arr)
            else:
                setattr(self, k, v)

    @classmethod
    def type(cls):
        return getattr(cls, '_type', cls.__name__.lower())


class ReqMixin(object):

    def _request(self, method, path, *args, **kwargs):
        headers = copy(self.auth)
        if kwargs:
            headers.update(kwargs)
        if 'content_type' in headers:
            headers['Content-Type'] = kwargs["content_type"]
        else:
            headers['Content-Type'] = "application/json"

        try:
            full_path = "/".join([self.path, path])
            LOG.info("Sending request to %s [%s]" % (full_path, kwargs))
            res = requests.request(method, full_path, data=json.dumps(kwargs),
                                   headers=headers)
            LOG.debug(res)
            if res.status_code == 401:
                raise NotAuthorized()
            if res.status_code == 302:
                raise NotModified()
            return res.json()
        except Exception, ex:
            LOG.exception(ex)
            return None


class ResourceManager(ReqMixin):

    def __init__(self, path, models, wrapper=None, selector=None, suffix=None):
        self.app_path = path
        if isinstance(models, (set, list, tuple)):
            self.models = models
            self.mixed = True
        else:
            self.models = [models]
            self.mixed = False
        self.wrapper = wrapper
        self.selector = selector
        self.suffix = suffix

    def _unwrap(self, res):
        items = []
        if self.mixed:
            tokens = self.wrapper.split(".")
            data = res
            for t in tokens:
                data = data[t]
            for model in self.models:
                _wrapper = getattr(model, 'wrapper', model.type()).lower()
                _wrapper = "%s%s" % (_wrapper, self.suffix)
                if _wrapper in data:
                    for i in data[_wrapper]:
                        print i, model
                        items.append(model(**i))
        else:
            _wrapper = self.wrapper or self.models[0].type()
            tokens = _wrapper.split(".")
            data = res
            for t in tokens:
                data = data[t]
            if isinstance(data, (set, list, tuple)):
                for item in data:
                    items.append(self.models[0](**item))
            else:
                return self.models[0](**data)
        return items

    def _get_selector(self, api):
        if self.selector:
            urlargs = str(getattr(api, self.selector))

        if not urlargs:
            urlargs = getattr(api, 'id') or ''
        urlargs = str(urlargs)
        return urlargs

    def list(self, *args, **kwargs):
        res = self._request('get', '/'.join([self.app_path] + list(args)),
                            **kwargs)
        items = []
        items = self._unwrap(res)
        return items

    def item(self, *args, **kwargs):
        if args and isinstance(args[0], ApiObject):
            api = args[0]
            urlargs = self._get_selector(api)
        else:
            urlargs = "/".join(args)

        res = self._request('get', '/'.join([self.app_path, urlargs]),
                            **kwargs)
        LOG.info(res)
        items = []
        items = self._unwrap(res)
        return items

    def add(self, model):
        res = self._request('post', self.app_path, **model._values)
        if res.get('success'):
            return True
        else:
            return "ERROR: " % res.get("error", {}).get("msg")

    def update(self, key, model):
        res = self._request(
            'get', '/'.join([self.app_path, key]), **model._values)
        if res.get('success'):
            return True
        else:
            return "ERROR: " % res.get("error", {}).get("msg")

    def replace(self, key, model):
        res = self._request('put', '/'.join([self.path, key]), **model._values)
        if res.get('success'):
            return True
        else:
            return "ERROR: " % res.get("error", {}).get("msg")

    def remove(self, key):
        if isinstance(key, ApiObject):
            name = key.name
        else:
            name = key
        res = self._request('delete', '/'.join([self.app_path, name]))
        if res.get('success'):
            return True
        else:
            return "ERROR: " % res.get("error", {}).get("msg")

_REST__subclasses = []


class RESTfulType(type):

    def __init__(cls, name, bases, dct):
        global __REST__subclasses
        if name == "RESTResource":
            cls._subclasses = _REST__subclasses
        else:
            for base in bases:
                if base.__name__ == "RESTResource":
                    _REST__subclasses.append(cls)
                    cls._resources = []

            for k, v in dct.items():
                if isinstance(v, ResourceManager):
                    cls._resources.append(v)

        super(RESTfulType, cls).__init__(name, bases, dct)

    def __call__(cls, *args, **kwargs):
        obj = super(RESTfulType, cls).__call__(*args, **kwargs)
        return obj


class RESTResource(ReqMixin):

    __metaclass__ = RESTfulType

    def __init__(self, auth=None, path=None):
        self.auth = auth
        self.path = path

        for res in self._resources:
            res.auth = self.auth
            res.path = self.path

    @classmethod
    def __subclasses__(cls):
        return self._subclasses
