from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QPushButton, QWidget, QHBoxLayout, QLabel, QLineEdit

from idarling.shared.models import Database


class RenameDialog(QDialog):
    """The dialog shown when an user wants to rename a project or a group."""

    def __init__(self, plugin, title, node, server=None):
        super(RenameDialog, self).__init__()
        self._plugin = plugin
        if isinstance(node, Database):
            self.item = node
        else:
            self.item = node.node
        # General setup of the dialog

        self._plugin.logger.debug("Showing rename {} dialog".format(self.item))
        self.setWindowTitle(title)
        icon_path = plugin.plugin_resource("settings.png")
        self.setWindowIcon(QIcon(icon_path))
        self.resize(100, 100)

        # Setup the layout and widgets
        layout = QVBoxLayout(self)
        qlabel_text = "<b>New " + str(self.item.__class__.__name__) + " Name</b>"
        self._rename_name_label = QLabel(qlabel_text)
        layout.addWidget(self._rename_name_label)
        self._new_name = QLineEdit()
        # Populate the field with the old name and already selected

        self._new_name.setText(self.item.name)
        self._new_name.setSelection(0, len(self.item.name))
        layout.addWidget(self._new_name)

        self._add_button = QPushButton("OK")
        self._add_button.clicked.connect(self.accept)
        down_side = QWidget(self)
        buttons_layout = QHBoxLayout(down_side)
        buttons_layout.addWidget(self._add_button)
        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(self._cancel_button)
        layout.addWidget(down_side)

    def get_result(self):
        return self._new_name.text(), self.item
