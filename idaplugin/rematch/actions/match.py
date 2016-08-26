import idaapi
import idc
from idautils import Functions

from ..idasix import QtCore, QtWidgets

from .. import instances
from .. import network, netnode
from . import base


class MatchAllAction(base.BoundFileAction):
  name = "&Match all"
  group = "Match"

  def activate(self, ctx):
    self.function_gen = enumerate(Functions())
    pd = QtWidgets.QProgressDialog(labelText="Processing...\nYou may continue "
                                             "working but avoid ground-"
                                             "breaking changes.",
                                   minimum=0, maximum=len(list(Functions())))
    self.progress = pd
    self.progress.canceled.connect(self.cancel)

    self.timer = QtCore.QTimer()
    self.timer.timeout.connect(self.perform_upload)
    self.timer.start()

    self.progress.accepted.connect(self.accepted_upload)

  def perform_upload(self):
    try:
      i, offset = self.function_gen.next()

      func = instances.FunctionInstance(netnode.bound_file_id, offset)
      network.query("POST", "collab/instances/", params=func.serialize(),
                    json=True)

      i = i + 1
      self.progress.setValue(i)
      if (i >= self.progress.maximum()):
        self.progress.accept()
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


# TODO: inherit logic in MatchAllAction
class MatchFunctionAction(base.BoundFileAction):
  name = "Match &Function"
  group = "Match"

  @staticmethod
  def activate(ctx):
    file_id = netnode.bound_file_id

    function = idaapi.choose_func("Choose function to match with database",
                                  idc.ScreenEA())
    if function is None:
      return

    data = instances.FunctionInstance(file_id, function.startEA)
    network.query("POST", "collab/instances/", params=data.serialize(),
                  json=True)
