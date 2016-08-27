import idaapi
import idc
import idautils

from ..idasix import QtCore, QtWidgets

from .. import instances
from .. import network, netnode
from . import base


class MatchAction(base.BoundFileAction):
  def activate(self, ctx):
    function_gen = self.get_functions()
    if not function_gen:
      return

    self.function_gen = enumerate(function_gen)
    pd = QtWidgets.QProgressDialog(labelText="Processing...\nYou may continue "
                                             "working but avoid ground-"
                                             "breaking changes.",
                                   maximum=self.get_functions_count())
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


class MatchAllAction(MatchAction):
  name = "&Match all"
  group = "Match"

  @staticmethod
  def get_functions():
    return idautils.Functions()

  @classmethod
  def get_functions_count(cls):
    return len(set(cls.get_functions()))


class MatchFunctionAction(MatchAction):
  name = "Match &Function"
  group = "Match"

  @staticmethod
  def get_functions():
    return idaapi.choose_func("Choose function to match with database",
                              idc.ScreenEA())

  @staticmethod
  def get_functions_count():
    return 1
