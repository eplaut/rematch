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
    self.task_id = None
    self.pbar = None

  def get_functions(self):
    if self.source == 'idb':
      return idautils.Functions()
    elif self.source == 'user':
      raise NotImplementedError("All user functions are not currently "
                                "supported as source value.")
    elif self.source == 'single':
      func = idaapi.choose_func("Choose function to match with database",
                                idc.ScreenEA())
      if not func:
        return None
      return [func.startEA]
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
    elif self.source == 'single':
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

    function_gen = self.get_functions()
    if not function_gen:
      return

    self.function_gen = enumerate(function_gen)
    self.pbar = QtWidgets.QProgressDialog()
    self.pbar.setLabelText("Processing IDB... You may continue working,\nbut "
                           "please avoid making any ground-breaking changes.")
    self.pbar.setRange(0, self.get_functions_count())
    self.pbar.setValue(0)
    self.pbar.canceled.connect(self.cancel_upload)
    self.pbar.accepted.connect(self.accepted_upload)

    self.timer.timeout.connect(self.perform_upload)
    self.timer.start(0)

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
      self.cancel_upload()
      raise

  def cancel_upload(self):
    self.timer.stop()
    self.timer.disconnect()
    self.pbar = None

  def accepted_upload(self):
    self.cancel_upload()

    params = {'action': 'commit', 'file': netnode.bound_file_id,
              'project': None}
    r = network.query("POST", "collab/tasks/", params=params, json=True)
    self.task_id = r['id']

    self.pbar = QtWidgets.QProgressDialog()
    self.pbar.setLabelText("Waiting for remote matching... You may continue "
                           "working without any limitations.")
    self.pbar.setRange(0, int(r['progress_max']))
    self.pbar.setValue(int(r['progress']))
    self.pbar.canceled.connect(self.cancel_task)
    self.pbar.accepted.connect(self.accepted_task)

    self.timer.timeout.connect(self.perform_task)
    self.timer.start(1000)

  def perform_task(self):
    try:
      r = network.query("GET", "collab/tasks/{}/".format(self.task_id),
                        json=True)

      self.pbar.setRange(0, int(r['progress_max']))
      self.pbar.setValue(int(r['progress']))
    except:
      self.cancel_task()

  def cancel_task(self):
    self.timer.stop()
    self.timer.disconnect()
    self.pbar = None

  def accepted_task(self):
    self.cancel_task()
