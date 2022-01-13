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
# import ctypes

import ida_auto
import ida_bytes
import ida_enum
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import ida_netnode
import ida_offset
import ida_pro
import ida_segment
import ida_struct
import ida_typeinf
import idaapi
import idc
from PyQt5.QtWidgets import QPlainTextEdit

from . import events as evt  # noqa: I100,I202
from .events import Event  # noqa: I201
from ..shared.commands import UpdateNotepad
from ..shared.local_types import ParseTypeString, ImportLocalType


class Hooks(object):
    """
    This is a common class for all client hooks. It adds an utility method to
    send an user event to all other clients through the server.
    """

    def __init__(self, plugin, orchestrator):
        self._plugin = plugin
        self.orchestrator = orchestrator

    def _send_packet(self, event):
        """Sends a packet to the server."""
        # Check if it comes from the auto-analyzer
        if ida_auto.get_auto_state() == ida_auto.AU_NONE:
            # little hack
            event.__dict__['token'] = self._plugin.token
            self._plugin.network.send_packet(event)
        else:
            # self._plugin.logger.debug("Ignoring a packet")
            pass


# See idasdk74.zip: idasdk74/include/idp.hpp for methods' documentation
# See C:\Program Files\IDA Pro 7.4\python\3\ida_idp.py for methods' prototypes
# The order for methods below is the same as the idp.hpp file to ease making changes
class IDBHooks(Hooks, ida_idp.IDB_Hooks):
    def __init__(self, plugin, orchestrator):
        ida_idp.IDB_Hooks.__init__(self)
        Hooks.__init__(self, plugin, orchestrator)
        self.last_local_type = None
        self.ea_enum = None
        self.plainTextEditor = None

    def hook_notepad(self, qwidget):
        # get the QPlainTextEdit children
        self.plainTextEditor = qwidget
        self.plainTextEditor.textChanged.connect(self.notepad_changed)

    def notepad_changed(self):
        text = self.plainTextEditor.toPlainText()
        if text != self._plugin.nodepad_content:
            self._send_packet(UpdateNotepad(text))
            self._plugin.nodepad_content = text
        return 0

    def ev_get_operand_string(self, insn, opnum):
        self._plugin.logger.debug("ev_get_operand_string() not implemented")

    def local_types_changed(self):
        changed_types = []
        # self._plugin.logger.trace(self._plugin.core.local_type_map)
        for i in range(1, ida_typeinf.get_ordinal_qty(ida_typeinf.get_idati())):
            t = ImportLocalType(i)
            if t and t.name and ida_struct.get_struc_id(t.name) == ida_idaapi.BADADDR and ida_enum.get_enum(
                    t.name) == ida_idaapi.BADADDR:
                if i in self._plugin.core.local_type_map:
                    t_old = self._plugin.core.local_type_map[i]
                    if t_old and not t.isEqual(t_old):
                        changed_types.append((t_old.to_tuple(), t.to_tuple()))
                    elif t_old is None and i in self._plugin.core.delete_candidates:
                        if not self._plugin.core.delete_candidates[i].isEqual(t):
                            changed_types.append((self._plugin.core.delete_candidates[i].to_tuple(), t.to_tuple()))
                        del self._plugin.core.delete_candidates[i]

                else:
                    changed_types.append((None, t.to_tuple()))
            if t is None:
                assert i in self._plugin.core.local_type_map
                if i in self._plugin.core.local_type_map:
                    t_old = self._plugin.core.local_type_map[i]
                    if t_old != t:
                        self._plugin.core.delete_candidates[i] = t_old
                    elif i in self._plugin.core.delete_candidates:
                        # changed_types.append((self._plugin.core.delete_candidates[i],None))
                        del self._plugin.core.delete_candidates[i]

                    # t_old = self._plugin.core.local_type_map[i]
                    # changed_types.append((t_old,None))
        # self._plugin.logger.trace(changed_types)

        self._plugin.logger.debug("Changed_types: %s" % list(
            map(lambda x: (x[0][0] if x[0] else None, x[1][0] if x[1] else None), changed_types)))
        if len(changed_types) > 0:
            self._send_packet(evt.LocalTypesChangedEvent(changed_types))
        self._plugin.core.update_local_types_map()
        return 0
        #     from .core import Core

        #     dll = Core.get_ida_dll()

        #     get_idati = dll.get_idati
        #     get_idati.argtypes = []
        #     get_idati.restype = ctypes.c_void_p

        #     get_numbered_type = dll.get_numbered_type
        #     get_numbered_type.argtypes = [
        #         ctypes.c_void_p,
        #         ctypes.c_uint32,
        #         ctypes.POINTER(ctypes.c_char_p),
        #         ctypes.POINTER(ctypes.c_char_p),
        #         ctypes.POINTER(ctypes.c_char_p),
        #         ctypes.POINTER(ctypes.c_char_p),
        #         ctypes.POINTER(ctypes.c_int),
        #     ]
        #     get_numbered_type.restype = ctypes.c_bool

        #     local_types = []
        #     py_ti = ida_typeinf.get_idati()
        #     for py_ord in range(1, ida_typeinf.get_ordinal_qty(py_ti)):
        #         name = ida_typeinf.get_numbered_type_name(py_ti, py_ord)

        #         ti = get_idati()
        #         ordinal = ctypes.c_uint32(py_ord)
        #         type = ctypes.c_char_p()
        #         fields = ctypes.c_char_p()
        #         cmt = ctypes.c_char_p()
        #         fieldcmts = ctypes.c_char_p()
        #         sclass = ctypes.c_int()
        #         get_numbered_type(
        #             ti,
        #             ordinal,
        #             ctypes.pointer(type),
        #             ctypes.pointer(fields),
        #             ctypes.pointer(cmt),
        #             ctypes.pointer(fieldcmts),
        #             ctypes.pointer(sclass),
        #         )
        #         local_types.append(
        #             (
        #                 py_ord,
        #                 name,
        #                 type.value,
        #                 fields.value,
        #                 cmt.value,
        #                 fieldcmts.value,
        #                 sclass.value,
        #             )
        #         )
        #     self._send_packet(evt.LocalTypesChangedEvent(local_types))
        return 0

    def ti_changed(self, ea, type, fname):
        self._plugin.logger.debug("ti_changed(ea = 0x%X, type = %s, fname = %s)" % (ea, type, fname))
        name = ""
        if ida_struct.is_member_id(ea):
            name = ida_struct.get_struc_name(ea)
        type = ida_typeinf.idc_get_type_raw(ea)
        self._send_packet(
            evt.TiChangedEvent(ea, (ParseTypeString(type[0]) if type else [], type[1] if type else None), name))
        return 0

    def op_ti_changed(self, ea, n, type, fnames):
        self._plugin.logger.debug("op_ti_changed() not implemented yet")
        return 0





    def op_type_changed(self, ea, n):
        self._plugin.logger.debug("op_type_changed")

        def gather_enum_info(ea, n):
            id = ida_bytes.get_enum_id(ea, n)[0]
            serial = ida_enum.get_enum_idx(id)
            return id, serial

        extra = {}
        mask = ida_bytes.MS_0TYPE if not n else ida_bytes.MS_1TYPE
        flags = ida_bytes.get_full_flags(ea) & mask
        t = ida_bytes.get_full_flags(ea)
        if n == 1:
            extra["bnot"] = ida_nalt.is__bnot1(ea)
            extra["invisgn"] = ida_nalt.is__invsign1(ea)
        elif n == 0:
            extra["bnot"] = ida_nalt.is__bnot0(ea)
            extra["invisgn"] = ida_nalt.is__invsign0(ea)

        def is_flag(type):
            return flags == mask & type

        def search_type_op_when_bad_flags(ea, n, operand_printable=None):
            """Try to fix 
            When a user presses the same key twice (Example b) the flags are not updated"""
            if operand_printable is None:
                last_char = idc.print_operand(ea, n)[-1]
            else:
                last_char = operand_printable[-1]
            if last_char == 'b':
                return "bin"
            elif last_char == 'o':
                return "oct"
            elif last_char == "'":
                return "chr"
            elif last_char == 'h':
                return "hex"
            elif last_char == ']':
                subString = idc.print_operand(ea,n)[:-1]
                return search_type_op_when_bad_flags(ea,n,subString)
            else:
                return "dec"

        # fix little bug replace ida_bytes.hex_flag() by idc.isHex
        # if is_flag(ida_bytes.hex_flag()):
        #   op = "hex"
        if n == 1 and idc.isHex1(t) or n == 0 and idc.isHex0(t):  # replace hex_flag
            op = "hex"
        elif n == 1 and idc.isDec1(t) or n == 0 and idc.isDec0(t):
            op = "dec"
        elif is_flag(ida_bytes.char_flag()):
            op = "chr"
        elif (n == 1 and idc.isBin1(t)) or (n == 0 and idc.isBin0(t)):
            op = "bin"
        elif is_flag(ida_bytes.oct_flag()):
            op = "oct"
        elif is_flag(ida_bytes.off_flag()):
            op = "offset"
            offbase = ida_offset.get_offbase(ea, n)
            extra["offbase"] = offbase
        elif is_flag(ida_bytes.enum_flag()):
            # tofix
            op = "enum"
            opinfo2 = idaapi.opinfo_t()
            idaapi.get_opinfo(opinfo2, ea, n, t)
            id, _ = gather_enum_info(ea, n)
            serial = opinfo2.ec.serial
            enum_name_parent = ida_enum.get_enum_name(id)
            extra["parent"] = enum_name_parent
            extra["serial"] = serial
            self._send_packet(evt.OpTypeChangedEvent(ea, n, "enum", extra))
            return
        elif (n == 1 and idc.is_stroff1(t)) or (n == 0 and idc.is_stroff0(t)):
            op = "struct"
            path = ida_pro.tid_array(1)
            delta = ida_pro.sval_pointer()
            path_len = ida_bytes.get_stroff_path(
                path.cast(), delta.cast(), ea, n
            )
            spath = []
            for i in range(path_len):
                sname = ida_struct.get_struc_name(path[i])
                spath.append(Event.decode(sname))
            extra["delta"] = delta.value()
            extra["spath"] = spath
        elif is_flag(ida_bytes.stkvar_flag()):
            op = "stkvar"
        elif ida_bytes.is_unknown(t):
            self._plugin.logger.debug("is unknown otp_changes")
            return 0
        elif (n == 1 and  idc.is_manual1(t)) or (n == 0 and idc.is_manual0(t)):
            manual_insn = idc.get_forced_operand(ea,n)
            extra["manual_insn"] = manual_insn
            op = "manual"
        # FIXME: No hooks are called when inverting sign
        # elif ida_bytes.is_invsign(ea, flags, n):
        #     op = 'invert_sign'
        elif n != -1:
            # @todo return one time (concat else and other send)
            op = search_type_op_when_bad_flags(ea, n)
            self._send_packet(evt.OpTypeChangedEvent(ea, n, op, extra))
            return 0
        else:
            disasm_line = idc.generate_disasm_line(ea, 0)
            # self.next_delay(ea,n)
            return
        self._send_packet(evt.OpTypeChangedEvent(ea, n, op, extra))

        return 0
        """
      # FIXME: Find a better way to do this
        """

    def changing_ti(self, ea, new_type, ew_fnames):
        self._plugin.logger.debug("changing_ti() not implemented")

    def changing_op_type(self, ea, n, opinfo):
        #Access to opinfo member's crash IDA :/
        return 0

    def enum_created(self, enum):
        name = ida_enum.get_enum_name(enum)
        self._send_packet(evt.EnumCreatedEvent(enum, name))
        return 0

    # XXX - use enum_deleted(self, id) instead?
    def deleting_enum(self, id):
        self._send_packet(evt.EnumDeletedEvent(ida_enum.get_enum_name(id)))
        return 0

    # XXX - use enum_renamed(self, id) instead?
    def renaming_enum(self, id, is_enum, newname):
        if is_enum:
            oldname = ida_enum.get_enum_name(id)
        else:
            oldname = ida_enum.get_enum_member_name(id)
        self._send_packet(evt.EnumRenamedEvent(oldname, newname, is_enum))
        return 0

    def enum_bf_changed(self, id):
        bf_flag = 1 if ida_enum.is_bf(id) else 0
        ename = ida_enum.get_enum_name(id)
        self._send_packet(evt.EnumBfChangedEvent(ename, bf_flag))
        return 0

    def enum_cmt_changed(self, tid, repeatable_cmt):
        cmt = ida_enum.get_enum_cmt(tid, repeatable_cmt)
        emname = ida_enum.get_enum_name(tid)
        self._send_packet(evt.EnumCmtChangedEvent(emname, cmt, repeatable_cmt))
        return 0

    def enum_member_created(self, id, cid):
        ename = ida_enum.get_enum_name(id)
        name = ida_enum.get_enum_member_name(cid)
        value = ida_enum.get_enum_member_value(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberCreatedEvent(ename, name, value, bmask)
        )
        return 0

    # XXX - use enum_member_deleted(self, id, cid) instead?
    def deleting_enum_member(self, id, cid):
        ename = ida_enum.get_enum_name(id)
        value = ida_enum.get_enum_member_value(cid)
        serial = ida_enum.get_enum_member_serial(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberDeletedEvent(ename, value, serial, bmask)
        )
        return 0

    def struc_created(self, tid):
        name = ida_struct.get_struc_name(tid)
        is_union = ida_struct.is_union(tid)
        self._send_packet(evt.StrucCreatedEvent(tid, name, is_union))
        return 0

    # XXX - use struc_deleted(self, struc_id) instead?
    def deleting_struc(self, sptr):
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.StrucDeletedEvent(sname))
        return 0

    def struc_align_changed(self, sptr):
        self._plugin.logger.debug("struc_align_changed() not implemented yet")
        return 0

    # XXX - use struc_renamed(self, sptr) instead?
    def renaming_struc(self, id, oldname, newname):
        self._send_packet(evt.StrucRenamedEvent(oldname, newname))
        return 0

    # XXX - use struc_expanded(self, sptr) instead 
    def expanding_struc(self, sptr, offset, delta):
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.ExpandingStrucEvent(sname, offset, delta))
        return 0

    def struc_member_created(self, sptr, mptr):
        extra = {}
        sname = ida_struct.get_struc_name(sptr.id)
        fieldname = ida_struct.get_member_name(mptr.id)
        offset = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        nbytes = mptr.eoff if mptr.unimem() else mptr.eoff - mptr.soff
        mt = ida_nalt.opinfo_t()
        is_not_data = ida_struct.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
            # Is it really possible to create an enum?
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
            elif flag & ida_bytes.stru_flag():
                extra["id"] = mt.tid
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
        else:
            self._send_packet(
                evt.StrucMemberCreatedEvent(
                    sname, fieldname, offset, flag, nbytes, extra
                )
            )
        return 0

    def struc_member_deleted(self, sptr, off1, off2):
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.StrucMemberDeletedEvent(sname, off2))
        return 0

    # XXX - use struc_member_renamed(self, sptr, mptr) instead?
    def renaming_struc_member(self, sptr, mptr, newname):
        sname = ida_struct.get_struc_name(sptr.id)
        offset = mptr.soff
        self._send_packet(evt.StrucMemberRenamedEvent(sname, offset, newname))
        return 0

    def struc_member_changed(self, sptr, mptr):
        extra = {}

        sname = ida_struct.get_struc_name(sptr.id)
        soff = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        mt = ida_nalt.opinfo_t()
        is_not_data = ida_struct.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, soff, mptr.eoff, flag, extra
                    )
                )
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, soff, mptr.eoff, flag, extra
                    )
                )
            elif flag & ida_bytes.stru_flag():
                extra["id"] = mt.tid
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, soff, mptr.eoff, flag, extra
                    )
                )
        else:
            self._send_packet(
                evt.StrucMemberChangedEvent(
                    sname, soff, mptr.eoff, flag, extra
                )
            )
        return 0

    def struc_cmt_changed(self, id, repeatable_cmt):
        fullname = ida_struct.get_struc_name(id)
        if "." in fullname:
            sname, smname = fullname.split(".", 1)
        else:
            sname = fullname
            smname = ""
        cmt = ida_struct.get_struc_cmt(id, repeatable_cmt)
        self._send_packet(
            evt.StrucCmtChangedEvent(sname, smname, cmt, repeatable_cmt)
        )
        return 0

    def segm_added(self, s):
        self._send_packet(
            evt.SegmAddedEvent(
                ida_segment.get_segm_name(s),
                ida_segment.get_segm_class(s),
                s.start_ea,
                s.end_ea,
                s.orgbase,
                s.align,
                s.comb,
                s.perm,
                s.bitness,
                s.flags,
            )
        )
        return 0

    # This hook lack of disable addresses option
    def segm_deleted(self, start_ea, end_ea):
        self._send_packet(evt.SegmDeletedEvent(start_ea))
        return 0

    def segm_start_changed(self, s, oldstart):
        self._send_packet(evt.SegmStartChangedEvent(s.start_ea, oldstart))
        return 0

    def segm_end_changed(self, s, oldend):
        self._send_packet(evt.SegmEndChangedEvent(s.end_ea, s.start_ea))
        return 0

    def segm_name_changed(self, s, name):
        self._send_packet(evt.SegmNameChangedEvent(s.start_ea, name))
        return 0

    def segm_class_changed(self, s, sclass):
        self._send_packet(evt.SegmClassChangedEvent(s.start_ea, sclass))
        return 0

    def segm_attrs_updated(self, s):
        self._send_packet(
            evt.SegmAttrsUpdatedEvent(s.start_ea, s.perm, s.bitness,s.comb,s.align,)
        )
        return 0

    def segm_moved(self, from_ea, to_ea, size, changed_netmap):
        self._send_packet(evt.SegmMoved(from_ea, to_ea, changed_netmap))
        return 0

    def allsegs_moved(self, info):
        self._plugin.logger.debug("allsegs_moved() not implemented yet")
        return 0

    def func_added(self, func):
        self._send_packet(evt.FuncAddedEvent(func.start_ea, func.end_ea))
        return 0

    def set_func_start(self, func, new_start):
        self._send_packet(evt.SetFuncStartEvent(func.start_ea, new_start))
        return 0

    def set_func_end(self, func, new_end):
        self._send_packet(evt.SetFuncEndEvent(func.start_ea, new_end))
        return 0

    def deleting_func(self, func):
        self._send_packet(evt.DeletingFuncEvent(func.start_ea))
        return 0

    def func_tail_appended(self, func, tail):
        self._send_packet(
            evt.FuncTailAppendedEvent(
                func.start_ea, tail.start_ea, tail.end_ea
            )
        )
        return 0

    def func_tail_deleted(self, func, tail_ea):
        self._send_packet(evt.FuncTailDeletedEvent(func.start_ea, tail_ea))
        return 0

    def tail_owner_changed(self, tail, owner_func, old_owner):
        self._send_packet(evt.TailOwnerChangedEvent(tail.start_ea, owner_func))
        return 0

    def func_noret_changed(self, pfn):
        self._plugin.logger.debug("func_noret_changed() not implemented yet")
        return 0

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        # FIXME: sgr_changed is not triggered when a segment register is
        # being deleted by the user, so we need to sent the complete list
        sreg_ranges = evt.SgrChanged.get_sreg_ranges(regnum)
        self._send_packet(evt.SgrChanged(regnum, sreg_ranges))
        return 0

    def destroyed_items(self, ea1, ea2, will_disable_range):
        # Instruction/data have been destroyed in [ea1,ea2)
        self._plugin.logger.debug("destroyed_items not implemented")

    def make_data(self, ea, flags, tid, size):
        self._plugin.logger.debug("make_data(ea = %x, flags = %x, tid = %x, size = %x)" % (ea, flags, tid, size))
        self._send_packet(
            evt.MakeDataEvent(ea, flags, size, ida_struct.get_struc_name(tid) if tid != ida_netnode.BADNODE else ''))
        return 0

    def renamed(self, ea, new_name, local_name):
        self._plugin.logger.debug("renamed(ea = %x, new_name = %s, local_name = %d)" % (ea, new_name, local_name))
        if ida_struct.is_member_id(ea) or ida_struct.get_struc(ea) or ida_enum.get_enum_name(ea):
            return 0
        self._send_packet(evt.RenamedEvent(ea, new_name, local_name))
        return 0

    def byte_patched(self, ea, old_value):
        self._plugin.logger.debug("Byte_pacthed %s %s " % (ea,old_value))
        self._send_packet(
            evt.BytePatchedEvent(ea, ida_bytes.get_wide_byte(ea))
        )
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
        cmt = "" if not cmt else cmt
        self._send_packet(evt.CmtChangedEvent(ea, cmt, repeatable_cmt))
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        self._send_packet(evt.RangeCmtChangedEvent(kind, a, cmt, repeatable))
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        print("extra_cmt_changed")
        print(f"Extra line is {ea}, {line_idx}, {cmt}")
        """       
        cmts = list()
        start = idaapi.E_PREV
        end = idaapi.get_first_free_extra_cmtidx(ea, start)
        for cmt in range(start, end):
            cmts.append(idaapi.get_extra_cmt(ea, cmt))
        print(f"cmts is {cmts}")
        self._send_packet(evt.ExtraCmtChangedEvent(ea, cmt, line_idx))
        cmts = list()
        start = idaapi.E_NEXT
        end = idaapi.get_first_free_extra_cmtidx(ea, start)
        for cmt in range(start, end):
            cmts.append(idaapi.get_extra_cmt(ea, cmt))
        print(f"cmts is {cmts}")
        self._send_packet(evt.ExtraCmtChangedEvent(ea, cmts, start))
        """
        self._send_packet(evt.ExtraCmtChangedEvent(ea, cmt, line_idx))

        return 0


    def item_color_changed(self, ea, color):
        # See #31 on fidgetingbits/IDArling
        # self._plugin.logger.debug("item_color_changed() not implemented yet")
        return 0

    def callee_addr_changed(self, ea, callee):
        self._plugin.logger.debug("callee_addr_changed() not implemented yet")
        return 0

    def bookmark_changed(self, index, pos, desc):
        rinfo = pos.renderer_info()
        plce = pos.place()
        ea = plce.touval(pos)
        if desc is None:  # set cmt to empty not None for delete bookmark
            desc = ""
        self._send_packet(evt.BookmarkChangedEvent(ea, index, desc))
        return 0

    def sgr_deleted(self, start_ea, end_ea, regnum):
        self._plugin.logger.debug("sgr_deleted() not implemented yet")
        return 0


class IDPHooks(Hooks, ida_idp.IDP_Hooks):
    def __init__(self, plugin, orchestrator):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, plugin, orchestrator)

    def ev_get_operand_string(self, insn, opnum):
        self._plugin.logger.debug("ev_getreg() not implemented")
        return ida_idp.IDP_Hooks.ev_get_operand_string(insn, opnum)

    def ev_getreg(self, regval, regnum):
        self._plugin.logger.debug("ev_getreg() not implemented")

    def ev_clean_tbit(self, ea, getreg, regvalues):
        self._plugin.logger.debug("ev_clean_tbit() not implemented")

    def ev_gen_regvar_def(self, outctx, v):
        ea = outctx.bin_ea
        func = idaapi.get_func(ea)
        canon_name = v.canon
        user_name = v.user
        cmt = v.cmt
        history_reg = None
        dict_reg_function = self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)] if (func.start_ea,
                                                                                                  func.end_ea) in self.orchestrator.ev_regvar_history else None
        if dict_reg_function is not None:
            history_reg = dict_reg_function[canon_name] if canon_name in dict_reg_function else None
        if dict_reg_function is None and history_reg is None:
            self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)] = dict()
            self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)][canon_name] = user_name, cmt
            self._send_packet(evt.GenRegvarDefEvent(ea, canon_name, user_name, cmt))
        elif dict_reg_function is not None and history_reg is None:
            self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)][canon_name] = user_name, cmt
            self._send_packet(evt.GenRegvarDefEvent(ea, canon_name, user_name, cmt))
        else:
            history_reg_user_name, history_reg_cmt = history_reg
            if history_reg_cmt != cmt or history_reg_user_name != user_name:
                # pop old value and send new
                self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)][canon_name] = user_name, cmt
                # send packet
                self._send_packet(evt.GenRegvarDefEvent(ea, canon_name, user_name, cmt))
        return 0

    def ev_adjust_argloc(self, *args):
        return ida_idp.IDP_Hooks.ev_adjust_argloc(self, *args)

    def ev_rename(self, ea, new_name):

        return ida_idp.IDP_Hooks.ev_rename(self, ea, new_name)

    def ev_ending_undo(self, action_name, is_undo):
        self._plugin.logger.debug("ev_ending_undo not implemented")
        return 0


    def ev_replaying_undo(self, action_name, vec, is_undo):
        self._plugin.logger.debug("ev_replaying_undo not implemented")
        return 0

    def ev_set_idp_options(self, keyword, value_type, value, errbuf, id):
        self._plugin.logger.debug("ev_set_idp_options not implemented")
        return ida_idp.IDP_Hooks.ev_set_idp_options(self, keyword, value_type, value, errbuf, id)

    def ev_get_stkarg_offset(self):
        self._plugin.logger.debug("ev_get_stkarg_offset not implemented : ")
        return ida_idp.IDP_Hooks.ev_get_stkarg_offset(self)


class HexRaysHooks(Hooks):
    def __init__(self, plugin, orchestrator):
        super(HexRaysHooks, self).__init__(plugin, orchestrator)
        self._available = None
        self._installed = False
        # We cache all HexRays data the first time we encounter a new function
        # and only send events to IDArling server if we didn't encounter the
        # specific data for a given function. This is just an optimization to 
        # reduce the amount of messages sent and replicated to other users
        self._cached_funcs = {}

    def hook(self):
        if self._available is None:
            if not ida_hexrays.init_hexrays_plugin():
                self._plugin.logger.info("Hex-Rays SDK is not available")
                self._available = False
            else:
                ida_hexrays.install_hexrays_callback(self._hxe_callback)
                self._available = True

        if self._available:
            self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    def _hxe_callback(self, event, *_):
        if not self._installed:
            return 0

        if event == ida_hexrays.hxe_func_printed:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            if func is None:
                return 0

            if func.start_ea not in self._cached_funcs.keys():
                self._cached_funcs[func.start_ea] = {}
                self._cached_funcs[func.start_ea]["labels"] = []
                self._cached_funcs[func.start_ea]["cmts"] = []
                self._cached_funcs[func.start_ea]["iflags"] = []
                self._cached_funcs[func.start_ea]["lvar_settings"] = []
                self._cached_funcs[func.start_ea]["numforms"] = []
            self._send_user_labels(func.start_ea)
            self._send_user_cmts(func.start_ea)
            self._send_user_iflags(func.start_ea)
            self._send_user_lvar_settings(func.start_ea)
            self._send_user_numforms(func.start_ea)
        return 0

    @staticmethod
    def _get_user_labels(ea):
        user_labels = ida_hexrays.restore_user_labels(ea)
        if user_labels is None:
            user_labels = ida_hexrays.user_labels_new()
        labels = []
        it = ida_hexrays.user_labels_begin(user_labels)
        while it != ida_hexrays.user_labels_end(user_labels):
            org_label = ida_hexrays.user_labels_first(it)
            name = ida_hexrays.user_labels_second(it)
            labels.append((org_label, Event.decode(name)))
            it = ida_hexrays.user_labels_next(it)
        ida_hexrays.user_labels_free(user_labels)
        return labels

    def _send_user_labels(self, ea):
        labels = HexRaysHooks._get_user_labels(ea)
        if labels != self._cached_funcs[ea]["labels"]:
            self._send_packet(evt.UserLabelsEvent(ea, labels))
            self._cached_funcs[ea]["labels"] = labels

    @staticmethod
    def _get_user_cmts(ea):
        user_cmts = ida_hexrays.restore_user_cmts(ea)
        if user_cmts is None:
            user_cmts = ida_hexrays.user_cmts_new()
        cmts = []
        it = ida_hexrays.user_cmts_begin(user_cmts)
        while it != ida_hexrays.user_cmts_end(user_cmts):
            tl = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            cmts.append(((tl.ea, tl.itp), Event.decode(str(cmt))))
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(user_cmts)
        return cmts

    def _send_user_cmts(self, ea):
        cmts = HexRaysHooks._get_user_cmts(ea)
        if cmts != self._cached_funcs[ea]["cmts"]:
            self._send_packet(evt.UserCmtsEvent(ea, cmts))
            self._cached_funcs[ea]["cmts"] = cmts

    @staticmethod
    def _get_user_iflags(ea):
        user_iflags = ida_hexrays.restore_user_iflags(ea)
        if user_iflags is None:
            user_iflags = ida_hexrays.user_iflags_new()
        iflags = []
        it = ida_hexrays.user_iflags_begin(user_iflags)
        while it != ida_hexrays.user_iflags_end(user_iflags):
            cl = ida_hexrays.user_iflags_first(it)
            f = ida_hexrays.user_iflags_second(it)

            # FIXME: Temporary while Hex-Rays update their API
            def read_type_sign(obj):
                import ctypes
                import struct

                buf = ctypes.string_at(id(obj), 4)
                return struct.unpack("I", buf)[0]

            f = read_type_sign(f)
            iflags.append(((cl.ea, cl.op), f))
            it = ida_hexrays.user_iflags_next(it)
        ida_hexrays.user_iflags_free(user_iflags)
        return iflags

    def _send_user_iflags(self, ea):
        iflags = HexRaysHooks._get_user_iflags(ea)
        if iflags != self._cached_funcs[ea]["iflags"]:
            self._send_packet(evt.UserIflagsEvent(ea, iflags))
            self._cached_funcs[ea]["iflags"] = iflags

    @staticmethod
    def _get_user_lvar_settings(ea):
        dct = {}
        lvinf = ida_hexrays.lvar_uservec_t()
        if ida_hexrays.restore_user_lvar_settings(lvinf, ea):
            dct["lvvec"] = []
            for lv in lvinf.lvvec:
                dct["lvvec"].append(HexRaysHooks._get_lvar_saved_info(lv))
            if hasattr(lvinf, "sizes"):
                dct["sizes"] = list(lvinf.sizes)
            dct["lmaps"] = []
            it = ida_hexrays.lvar_mapping_begin(lvinf.lmaps)
            while it != ida_hexrays.lvar_mapping_end(lvinf.lmaps):
                key = ida_hexrays.lvar_mapping_first(it)
                key = HexRaysHooks._get_lvar_locator(key)
                val = ida_hexrays.lvar_mapping_second(it)
                val = HexRaysHooks._get_lvar_locator(val)
                dct["lmaps"].append((key, val))
                it = ida_hexrays.lvar_mapping_next(it)
            dct["stkoff_delta"] = lvinf.stkoff_delta
            dct["ulv_flags"] = lvinf.ulv_flags
        return dct

    @staticmethod
    def _get_lvar_saved_info(lv):
        return {
            "ll": HexRaysHooks._get_lvar_locator(lv.ll),
            "name": Event.decode(lv.name),
            "type": HexRaysHooks._get_tinfo(lv.type),
            "cmt": Event.decode(lv.cmt),
            "flags": lv.flags,
        }

    @staticmethod
    def _get_tinfo(type):
        if type.empty():
            return None, None, None

        type, fields, fldcmts = type.serialize()
        type = Event.decode_bytes(type)
        fields = Event.decode_bytes(fields)
        fldcmts = Event.decode_bytes(fldcmts)
        return type, fields, fldcmts

    @staticmethod
    def _get_lvar_locator(ll):
        return {
            "location": HexRaysHooks._get_vdloc(ll.location),
            "defea": ll.defea,
        }

    @staticmethod
    def _get_vdloc(location):
        return {
            "atype": location.atype(),
            "reg1": location.reg1(),
            "reg2": location.reg2(),
            "stkoff": location.stkoff(),
            "ea": location.get_ea(),
        }

    def _send_user_lvar_settings(self, ea):
        lvar_settings = HexRaysHooks._get_user_lvar_settings(ea)
        if lvar_settings != self._cached_funcs[ea]["lvar_settings"]:
            self._send_packet(evt.UserLvarSettingsEvent(ea, lvar_settings))
            self._cached_funcs[ea]["lvar_settings"] = lvar_settings

    @staticmethod
    def _get_user_numforms(ea):
        user_numforms = ida_hexrays.restore_user_numforms(ea)
        if user_numforms is None:
            user_numforms = ida_hexrays.user_numforms_new()
        numforms = []
        it = ida_hexrays.user_numforms_begin(user_numforms)
        while it != ida_hexrays.user_numforms_end(user_numforms):
            ol = ida_hexrays.user_numforms_first(it)
            nf = ida_hexrays.user_numforms_second(it)
            numforms.append(
                (
                    HexRaysHooks._get_operand_locator(ol),
                    HexRaysHooks._get_number_format(nf),
                )
            )
            it = ida_hexrays.user_numforms_next(it)
        ida_hexrays.user_numforms_free(user_numforms)
        return numforms

    @staticmethod
    def _get_operand_locator(ol):
        return {"ea": ol.ea, "opnum": ol.opnum}

    @staticmethod
    def _get_number_format(nf):
        return {
            "flags": nf.flags,
            "opnum": nf.opnum,
            "props": nf.props,
            "serial": nf.serial,
            "org_nbytes": nf.org_nbytes,
            "type_name": nf.type_name,
        }

    def _send_user_numforms(self, ea):
        numforms = HexRaysHooks._get_user_numforms(ea)
        if numforms != self._cached_funcs[ea]["numforms"]:
            self._send_packet(evt.UserNumformsEvent(ea, numforms))
            self._cached_funcs[ea]["numforms"] = numforms

    def microcode(self, mba):
        self._plugin.logger.debug("microcode is not implemented")
        return HexRaysHooks.microcode(self, mba)

    def text_ready(self, vu):
        self._plugin.logger.debug("text_ready is not implemented")
        return HexRaysHooks.text_ready(self, vu)

    def structural(self, ct):
        self._plugin.logger.debug("text_ready is not implemented")
        return HexRaysHooks.structural(self, ct)

    def keyboard(self, vu, key_code, shift_state):
        self._plugin.logger.debug("keyboard is not implemented")
        return HexRaysHooks.keyboard(self, vu, key_code, shift_state)

    def lvar_cmt_changed(self, vu, v, cmt):
        self._plugin.logger.debug("lvar_cmt_changed is not implemented")
        return HexRaysHooks.keyboard(self, vu, v, cmt)

    def maturity(self, cfunc, new_maturity):
        self._plugin.logger.debug("maturity is not implemented")
        return HexRaysHooks.maturity(self, cfunc, new_maturity)

class MyDbgHook(Hooks,idaapi.DBG_Hooks):

    def __init__(self, plugin, orchestrator):
        idaapi.DBG_Hooks.__init__(self)
        Hooks.__init__(self, plugin, orchestrator)
        self._installed = False




    def unhook(self):
        if self._installed:
            self._plugin.logger.info("Uninstalling debuger hook")
            super(MyDbgHook, self).unhook()
            self._plugin.logger.info("Debuger hook successfully uninstalling.")
        else:
            self._plugin.logger.info("Debugger hook already uninstalled")

    def dbg_process_start(self,pid,tid,ea,name,base,size):
        self._plugin.logger.info("dbg_process_start")
        #stop event send
        self._plugin.core.unhook_all()
        return

    def dbg_process_exit(self,pid,tid,ea,code):
        self._plugin.logger.info("dbg_process_Exit")
        self._plugin.core.hook_all()
        return


    def dbg_run_to(self,pid,tid=0,ea=0):
        self._plugin.logger.info("dbg_run_to")
        return

class UIHooks(Hooks,ida_kernwin.UI_Hooks):

    def __init__(self, plugin, orchestrator):
        ida_kernwin.UI_Hooks.__init__(self)
        Hooks.__init__(self, plugin, orchestrator)
        self.actions = []
        self.actions_history = None
        self.history = None

    def saved(self):
        self._plugin.logger.debug("saved not implemented")

    def saving(self):
        self._plugin.logger.debug("saving not implemented")

    def ready_to_run(self):
        self._plugin.logger.debug("ready_to_run not implemented")

    def resume(self):
        self._plugin.logger.debug("resume not implemented")

    def updated_action(self):
        self._plugin.logger.debug("updated_action not implemented")

    def updating_actions(self, ctx):
        """
        self._plugin.logger.debug("ctx is : " + str(ctx.action))
        self._plugin.logger.debug("updating_actions not implemented")
        """

    def database_inited(self, is_new_database, idc_script):
        self._plugin.logger.debug("database_inited not implemented")

    def idcstart(self):
        self._plugin.logger.debug("idcstart not implemented")

    def idcstop(self):
        self._plugin.logger.debug("idcstop not implemented")

    def preprocess_action(self, name):
        ea = ida_kernwin.get_screen_ea()
        self._plugin.logger.debug("preprocess_action(name = %s). ea = 0x%x." % (name, ea))
        if name == "MakeCode":
            self._plugin.logger.warning("This feature 'make code' may present bugs")
            self.actions.append((name, ea))
        elif name == "MakeUnknown":
            self._plugin.logger.warning("This feature 'make unknown' may present bugs")
            self.actions.append((name, ea))
        elif name == "ChooserDelete":
            self.actions.append((name, ea))
        elif name == "BreakpointToggle":
            self.actions.append((name,ea))
        elif name == "OpNumber":
            self.actions.append((name, ea))
        elif name == "MakeName":
            self.actions.append((name, ea))
        elif name == "MakeExtraLineB":
            self.actions.append((name, ea))
        elif name == "MakeExtraLineA":
            pass
            #self.actions.append((name, ea))
        elif name in ("MakeStrlit", "StringC", "StringDOS",
                      "StringPascal1", "StringPascal2", "StringUnicode",
                      "StringDelphi", "StringUnicode", "StringUnicodePascal2",
                      "StringUnicodePascal4"):
            self.actions.append((name, ea))
        elif name == "ChooserEdit":
            self.actions.append((name, ea))
        elif name == "ChooserDelete":
            # check index of
            self.actions.append((name, ea))
        elif name == "JumpPosition":
            self.history = list()
            index = 0
            for slot in range(0, 1025):
                ea_bookmark = idc.get_bookmark(slot)
                description = idc.get_bookmark_desc(slot)
                if ea_bookmark == idaapi.BADADDR:
                    continue
                else:
                    self.history.append((index, ea_bookmark, description))
                    index += 1
            self.actions_history = (name, ea)
        elif name == "PatchedBytes":
            self.actions_history = (name, ea)
        elif name == "RenameRegister":
            self.actions.append((name, ea))
        elif name == "ManualInstruction":
            self._plugin.logger.warning("This feature 'manual instruction' may present bugs")
            self.actions.append((name, ea))
        return 0


    def postprocess_action(self):
        self._plugin.logger.debug("postprocess_action()")
        if len(self.actions):
            self._plugin.logger.debug("previous_name : %s" % str(self.actions_history))
            name, ea = self.actions.pop()
            if self.actions_history is not None:
                previous_name, previous_ea = self.actions_history
            else:
                previous_name, previous_ea = None, None
            if name == "MakeCode":
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_code(flags):
                    sizeItem = ida_bytes.get_item_size(ea)
                    self._send_packet(evt.MakeCodeEvent(ea, sizeItem))
            elif name == "MakeUnknown":
                flags = ida_bytes.get_full_flags(ea)
                if ida_bytes.is_unknown(flags):
                    self._send_packet(evt.MakeUnknown(ea))
            elif name == "ChooserDelete" and self.actions_history == "PatchedBytes":
                self._send_packet(evt.DeletePatchedByte(ea))
            elif name == "OpNumber":
                self._send_packet(evt.DefaultOpNumber(ea))
            elif name == "BreakpointToggle":
                self._plugin.logger.debug(f"BreakpointToggle at : {ea} is exist {idaapi.exist_bpt(ea)}")
                self._send_packet(evt.BreakPointToggle(ea,idaapi.exist_bpt(ea)))
                """
                elif name == "MakeName":
                    pass
                   
                    elif name in ("MakeExtraLineB", "MakeExtraLineA"):
                        cmts = list()
                        start = idaapi.E_NEXT if name == "MakeExtraLineB" else idaapi.E_PREV
                        end = idaapi.get_first_free_extra_cmtidx(ea, start)
                        for cmt in range(start, end):
                            cmts.append(idaapi.get_extra_cmt(ea, cmt))
                        self._send_packet(evt.ExtraCmtChangedEvent(ea, cmts, start))
                """
            elif name in ("MakeStrlit", "StringC", "StringDOS",
                          "StringPascal1", "StringPascal2", "StringUnicode",
                          "StringDelphi", "StringUnicode", "StringUnicodePascal2",
                          "StringUnicodePascal4"):
                str_type = idc.get_str_type(ea)
                if str_type is None:
                    # check previous type
                    ea_bis = ea
                    while str_type is None:
                        ea_bis = ida_bytes.prev_addr(ea_bis)
                        str_type = idc.get_str_type(ea_bis)
                size = 0
                if str_type == 0x2000001:
                    size = ida_bytes.get_item_size(ea)
                self._send_packet(evt.ConvertStringType(ea, size, str_type))
            elif name == "ChooserEdit" and previous_name == "JumpPosition":
                description = None
                index = 0
                current_slot = list()
                for slot in range(0, 1025):
                    ea_bookmark = idc.get_bookmark(slot)
                    description = idc.get_bookmark_desc(slot)
                    if ea_bookmark == idaapi.BADADDR:
                        continue
                    else:
                        current_slot.append((index, ea_bookmark, description))
                        index += 1
                # check wich bookmark was edited
                for current_bookmark in current_slot:
                    if current_bookmark not in self.history:
                        index, ea_bookmark, description = current_bookmark
                        # search bookmark's index and ea identical
                        self._send_packet(evt.BookmarkChangedEvent(ea, index, description))
                self.history = current_slot
            elif name == "ChooserDelete" and previous_name == "JumpPosition":
                current_slot = list()
                index = 0
                for slot in range(0, 1025):
                    ea_bookmark = idc.get_bookmark(slot)
                    description = idc.get_bookmark_desc(slot)
                    if ea_bookmark == idaapi.BADADDR:
                        continue
                    else:
                        current_slot.append((index, ea_bookmark, description))
                        index += 1
                deleted_items = [item for item in self.history if item[1] not in [a[1] for a in current_slot]]
                for to_delete in deleted_items:
                    index, ea_bookmark, description = to_delete
                    self._send_packet(evt.BookmarkChangedEvent(ea, index, ""))
                self.history = current_slot
            elif name == "RenameRegister":
                func = idaapi.get_func(ea)
                a = func.regvars
                reg_size = a.count
                # retrieve all register renamed in history
                func_history_regvar = self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)] if (
                                                                                                           func.start_ea,
                                                                                                           func.end_ea) in self.orchestrator.ev_regvar_history else None
                if func_history_regvar is None:
                    return
                current_regvar = list()
                for i in range(reg_size):
                    reg = a.__getitem__(i)
                    cmt = reg.cmt
                    canon_name = reg.canon
                    user_name = reg.user
                    current_regvar.append(canon_name)
                for history_canon_name, _ in func_history_regvar.items():
                    if history_canon_name not in current_regvar:
                        # delete regvar
                        self.orchestrator.ev_regvar_history[(func.start_ea, func.end_ea)].pop(history_canon_name)
                        self._send_packet(evt.GenRegvarDefEvent(ea, history_canon_name, "", ""))
            elif name == "ManualInstruction":

                insn = ida_bytes.get_manual_insn(ea) if ida_bytes.get_manual_insn(ea) is not None else ""
                self._send_packet(evt.ManualInsnEvent(ea, insn))
