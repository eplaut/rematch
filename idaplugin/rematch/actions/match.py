import idaapi
import idc
import idautils

from ..idasix import QtCore, QtWidgets

from ..dialogs.match import MatchDialog

from .. import instances
from .. import network, netnode
from . import base


class MatchAction(base.BoundFileAction):
  name = "&Match"

  def __init__(self, *args, **kwargs):
    super(MatchAction, self).__init__(*args, **kwargs)
    self.function_gen = None
    self.pbar = None
    self.timer = QtCore.QTimer()
    self.source = None
    self.target = None
    self.methods = []

  def activate(self, ctx):
    dialog = MatchDialog()
    self.source, self.target, self.methods = dialog.get()
    print(self.source, self.target, self.methods)

    function_gen = self.get_functions()
    if not function_gen:
      return

    self.function_gen = enumerate(function_gen)
    pd = QtWidgets.QProgressDialog(labelText="Processing...\nYou may continue "
                                             "working but avoid ground-"
                                             "breaking changes.",
                                   maximum=self.get_functions_count())
    self.pbar = pd
    self.pbar.canceled.connect(self.cancel)

    self.timer.timeout.connect(self.perform_upload)
    self.timer.start()

    self.pbar.accepted.connect(self.accepted_upload)

  def perform_upload(self):
    try:
      i, offset = self.function_gen.next()

      func = instances.FunctionInstance(netnode.bound_file_id, offset)
      network.query("POST", "collab/instances/", params=func.serialize(),
                    json=True)

      i = i + 1
      self.pbar.setValue(i)
      if i >= self.pbar.maximum():
        self.pbar.accept()
    except:
      self.timer.stop()
      raise

  def cancel(self):
    self.timer.stop()

  def accepted_upload(self):
    self.timer.stop()
    self.timer.disconnect()

    # TODO: ask for project to compare against
    task_params = {'action': 'commit', 'file': netnode.bound_file_id,
                   'project': None}
    r = network.query("POST", "collab/tasks/", params=task_params, json=True)
    print(r)