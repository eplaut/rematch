try:
  from PyQt5 import QtWidgets
except ImportError:
  from PySide import QtGui
  QtWidgets = QtGui

from . import base


class MatchDialog(base.BaseDialog):
  def __init__(self, **kwargs):
    super(MatchDialog, self).__init__(title="Match", **kwargs)

    self.sourceGrp = self.add_radio_group("Match source",
                                          ("Entire IDB", 'idb'),
                                          ("User functions", 'user'),
                                          ("Single function", 'single'),
                                          ("Range", 'range'))

    self.targetGrp = self.add_radio_group("Match target",
                                          ("Entire DB", 'db'),
                                          ("Project", 'project'),
                                          ("Another file", 'file'))

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

    self.bottom_layout(self.accept, "&Start matching")

  def data(self):
    source = self.get_radio_result(self.sourceGrp)
    target = self.get_radio_result(self.targetGrp)
    methods = []
    if self.identity.isChecked():
      methods.append('identity')
    if self.fuzzy.isChecked():
      methods.append('fuzzy')
    if self.graph.isChecked():
      methods.append('graph')

    return source, target, methods
