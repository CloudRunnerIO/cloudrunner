from base import ApiObject, ResourceManager, RESTResource


class Repository(ApiObject):
    pass


class Folder(ApiObject):
    pass


class Script(ApiObject):
    pass


class Library(RESTResource):

    repositories = ResourceManager('library/repo', Repository,
                                   wrapper='repositories')
    folder = ResourceManager('library/folder', Folder)
    script = ResourceManager('library/script', Script)
    browser = ResourceManager('library/browse',
                              [Folder, Script], wrapper='contents', suffix='s')
