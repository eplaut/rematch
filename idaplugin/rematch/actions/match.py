from ..idasix import QtCore, QtWidgets
import idautils
import idaapi
import idc

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

  def get_functions(self):
    if self.source == 'idb':
      return idautils.Functions()
    elif self.source == 'user':
      raise NotImplementedError("All user functions are not currently "
                                "supported as source value.")
    elif self.source == 'single':
      return idaapi.choose_func("Choose function to match with database",
                                idc.ScreenEA())
    elif self.source == 'range':
      raise NotImplementedError("Range of addresses is not currently "
                                "supported as source value.")

    raise ValueError("Invalid source value received from MatchDialog: {}"
                     "".format(self.source))

  def get_functions_count(self):
    if self.source == 'idb':
      return len(set(idautils.Functions()))
    elif self.source == 'user':
      raise NotImplementedError("All user functions are not currently "
                                "supported as source value.")
    elif self.soruce == 'single':
      return 1
    elif self.source == 'range':
      raise NotImplementedError("Range of addresses is not currently "
                                "supported as source value.")

    raise ValueError("Invalid source value received from MatchDialog: {}"
                     "".format(self.source))

  def activate(self, ctx):
    dialog = MatchDialog()
    data, _, result = dialog.get()

    if result is None:
      return

    self.source, self.target, self.methods = data
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
