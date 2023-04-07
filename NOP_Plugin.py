import ida_bytes
import idautils
import idaapi
import idc

class NopPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "NOP selected instructions"
    help = "This plugin allows you to NOP selected instructions to remove junk bytes / instructions"
    wanted_name = "NOPPlugin"
    wanted_hotkey = "Shift+Z"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        # Get the selected instructions
        selection = []
        selstart, selend = idc.read_selection_start(), idc.read_selection_end()
        if selstart == idc.BADADDR or selend == idc.BADADDR:
            print("Select an instruction or a range of instructions.")
            return
        for head in idautils.Heads(selstart, selend):
            selection.append(head)

        # NOP the selected instructions
        for ea in selection:
            length = ida_bytes.get_item_size(ea)
            nop_opcode = b"\x90" * length
            ida_bytes.patch_bytes(ea, nop_opcode)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return NopPlugin()
