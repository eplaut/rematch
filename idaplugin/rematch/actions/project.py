from . import base
from ..dialogs.project import AddProjectDialog, AddFileDialog

from .. import netnode, network, logger, exceptions


class AddProjectAction(base.AuthAction):
  name = "&Add project"
  group = "Project"
  dialog = AddProjectDialog

  @staticmethod
  def submit_handler(name, description, private, bind_current):
    data = {'name': name, 'description': description, 'private': private,
            'files': []}

    if bind_current:
      data['files'].append(netnode.bound_file_id)

    try:
      resp = network.QueryWorker("POST", "collab/projects/", params=data,
                                 json=True)
    except exceptions.QueryException as e:
      data = e.response()
      if "Invalid pk" in data['file'][0]:
        logger('MatchAllAction').error("Something wrong happened, we can't"
                                       " find the right database to fetch"
                                       "infomation from.\nAre you sure you'"
                                       "re usig the right server ?\nDid you"
                                       "create a new database ?")
    return resp


class AddFileAction(base.UnboundFileAction):
  name = "&Add file"
  group = "Project"
  dialog = AddFileDialog

  @staticmethod
  def submit_handler(project, name, md5hash, description, shareidb):
    # TODO: search for files with the same hash
    data = {'project': project, 'name': name, 'md5hash': md5hash,
            'description': description, 'instances': []}

    if shareidb:
      # TODO: uploadfile
      pass

    try:
      resp = network.QueryWorker("POST", "collab/files/", params=data,
                                 json=True)
    except exceptions.QueryException as e:
      data = e.response()
      if "Invalid pk" in data['file'][0]:
        logger('MatchAllAction').error("Something wrong happened, we can't"
                                       " find the right database to fetch"
                                       "infomation from.\nAre you sure you'"
                                       "re usig the right server ?\nDid you"
                                       "create a new database ?")
    return resp

  @staticmethod
  def response_handler(response):
    netnode.bound_file_id = response['id']
    return True
