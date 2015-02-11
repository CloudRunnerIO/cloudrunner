import logging

LOG = logging.getLogger("ApiClient")

from base import *  # noqa
from exceptions import *  # noqa
from nodes import *  # noqa
from library import *  # noqa
from logs import *  # noqa


class RESTfulClient(ReqMixin):

    def __init__(self, auth_username, auth_pass=None, auth_token=None,
                 rest_path="https://api.cloudrunner.io"):
        self.path = rest_path
        self.auth = {}
        if auth_pass:
            # Request token
            res = self._request('post', 'auth/login',
                                username=auth_username, password=auth_pass)
            if not res:
                raise Exception("Cannot connect to server")
            if "login" not in res:
                raise NotAuthorized()
            auth_token = res['login']['token']
            self.auth = {'Cr-User': auth_username,
                         'Cr-Token': auth_token}
        elif auth_token:
            self.auth = {'Cr-User': auth_username,
                         'Cr-Token': auth_token}
        else:
            raise Misconnfigured("Either pass or token should be provided")

    def __getattr__(self, k):
        for c in RESTResource._subclasses:
            if c.__name__.lower() == k.lower():
                obj = c(auth=self.auth, path=self.path)
                return obj
        raise NotImplemented

Client = RESTfulClient
