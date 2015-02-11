from base import ApiObject, ResourceManager, RESTResource


class Log(ApiObject):
    pass


class Logs(RESTResource):

    get = ResourceManager('logs/get', Log, selector='group',
                          wrapper='group')
    search = ResourceManager('logs/search', Log, wrapper='tasks.groups')
    latest = ResourceManager('logs/all', Log, wrapper='tasks.groups')
    output = ResourceManager('logs/output', Log, wrapper='outputs',
                             selector='id:uuid')
