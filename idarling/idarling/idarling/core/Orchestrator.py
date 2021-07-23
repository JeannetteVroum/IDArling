# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import idaapi
import idautils


class Orchestrator(object):

    def __init__(self, plugin):
        # History of regvar prevents the sending of changes already been sent
        self.ev_regvar_history = dict()
        self._plugin = plugin

    def analyze(self):
        acc = 0
        start_ea_funcs_gen = idautils.Functions()
        for start_ea in start_ea_funcs_gen:
            func = idaapi.get_func(start_ea)
            func_regvars = func.regvars
            size_reg = func_regvars.count
            if size_reg > 0:
                if not (func.start_ea, func.end_ea) in self.ev_regvar_history:
                    self.ev_regvar_history[(func.start_ea, func.end_ea)] = dict()
                table_regvar = func.__get_regvars__()
                for reg in table_regvar:
                    if reg is not None:
                        try:
                            acc += 1
                        except:
                            pass
        self._plugin.logger.debug("%d renamed register found " % acc)

    def append(self, reg, func):
        self.ev_regvar_history[(func.start_ea, func.end_ea)][reg.canon] = (reg.user, reg.cmt)

    def refresh(self):
        pass
