from base import ApiObject, ResourceManager, RESTResource


class Node(ApiObject):
    pass


class Nodes(RESTResource):

    nodes = ResourceManager('manage/nodes', Node, wrapper='nodes')
