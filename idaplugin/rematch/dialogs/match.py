from ..idasix import QtWidgets

from . import base
from .. import netnode


class MatchDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(MatchDialog, self).__init__(title="Match", **kwargs)

    self.source_single = base.QFunctionSelect()
    self.source_range = base.QFunctionRangeSelect()
    choices = [("Entire IDB", 'idb', None),
               ("User functions", 'user', None),
               ("Single function", 'single', self.source_single),
               ("Range", 'range', self.source_range)]
    self.sourceGrp = self.create_radio_group("Match source", *choices)

    self.target_project = self.create_item_select('projects', allow_none=False)
    self.target_file = self.create_item_select('files', allow_none=False,
                                               exclude=[netnode.bound_file_id])
    choices = [("Entire DB", 'db', None),
               ("Project", 'project', self.target_project),
               ("Another file", 'file', self.target_file)]
    self.targetGrp = self.create_radio_group("Match target", *choices)

    self.identity = QtWidgets.QCheckBox("Identify matches")
    self.fuzzy = QtWidgets.QCheckBox("Fuzzy matches")
    self.graph = QtWidgets.QCheckBox("Graph matches")
    self.identity.setChecked(True)
    self.fuzzy.setChecked(True)
    self.graph.setChecked(True)
    methodLyt = QtWidgets.QVBoxLayout()
    methodLyt.addWidget(self.identity)
    methodLyt.addWidget(self.fuzzy)
    methodLyt.addWidget(self.graph)

    methodGbx = QtWidgets.QGroupBox("Match methods")
    methodGbx.setLayout(methodLyt)
    self.base_layout.addWidget(methodGbx)

    self.bottom_layout("&Start matching")

  def data(self):
    methods = []
    if self.identity.isChecked():
      methods.append('identity')
    if self.fuzzy.isChecked():
      methods.append('fuzzy')
    if self.graph.isChecked():
      methods.append('graph')

    return {'source': self.get_radio_result(self.sourceGrp),
            'source_single': self.source_single.func.startEA,
            'source_range': [self.source_range.start.func.startEA,
                             self.source_range.end.func.endEA],
            'target': self.get_radio_result(self.targetGrp),
            'target_project': self.target_project.currentData(),
            'target_file': self.target_file.currentData(),
            'methods': methods}
