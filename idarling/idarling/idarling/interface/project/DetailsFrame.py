#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program. If not, see <http://www.gnu.org/licenses/>.
from PyQt5.QtWidgets import QVBoxLayout, QWidget, QGroupBox, QGridLayout, QLabel

from idarling.shared.models import File


class DetailFrame(QWidget):
    def __init__(self, parent, plugin):
        super(DetailFrame, self).__init__()
        self._plugin = plugin
        self._parent = parent
        self.right_side = parent.right_side
        self.right_layout = QVBoxLayout(self.right_side)
        parent.right_layout = self.right_layout
        details_group = QGroupBox("Details", self.right_side)
        details_layout = QGridLayout(details_group)
        self._file_label = QLabel("<b>File:</b>                           ")
        details_layout.addWidget(self._file_label, 0, 0)
        self._hash_label = QLabel("<b>Hash:</b>                           ")
        details_layout.addWidget(self._hash_label, 1, 0)
        details_layout.setColumnStretch(0, 1)
        self._type_label = QLabel("<b>Type:</b>                           ")
        details_layout.addWidget(self._type_label, 0, 1)
        self._date_label = QLabel("<b>Date:</b>                           ")
        details_layout.addWidget(self._date_label, 1, 1)
        details_layout.setColumnStretch(2, 2)
        self.right_layout.addWidget(details_group)

    def populate(self, file: File) -> None:
        """
         Populate information about file
        :param project: project
        """
        self._file_label.setText("<b>File:</b> %s" % str(file.file))
        self._hash_label.setText("<b>Hash:</b> %s" % str(file.hash))
        self._type_label.setText("<b>Type:</b> %s" % str(file.ftype))
        self._date_label.setText("<b>Date:</b> %s" % str(file.date))
        self._plugin.logger.debug("Geometry is " + str(self.size()))

    def clean(self) -> None:
        """
        Clean information about file in view
        """
        self._file_label.setText("<b>File:</b>                           ")
        self._hash_label.setText("<b>Hash:</b>                           ")
        self._type_label.setText("<b>Type:</b>                           ")
        self._date_label.setText("<b>Date:</b>                           ")
        self._plugin.logger.debug("Geometry is " + str(self.size()))
