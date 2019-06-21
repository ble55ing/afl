#! /usr/bin/env python
 
import angr
from angrutils import plot_cfg
 
 
def analyze(b, addr, name=None):
    start_state = b.factory.blank_state(addr=addr)
    start_state.stack_push(0x0)
    cfg = b.analyses.CFGAccurate(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
    for addr,func in proj.kb.functions.iteritems():
        if func.name in ['main','verify']:
            plot_cfg(cfg, "%s_%s_cfg" % (name, func.name), asminst=True, vexinst=False, func_addr={addr:True}, debug_info=False, remove_imports=True, remove_path_terminator=True)
 
    plot_cfg(cfg, "%s_cfg" % (name), asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
    plot_cfg(cfg, "%s_cfg" % (name), format="dot",asminst=True, vexinst=False, debug_info=False, remove_imports=True, remove_path_terminator=True)
    plot_cfg(cfg, "%s_cfg_full" % (name), asminst=True, vexinst=True, debug_info=True, remove_imports=False, remove_path_terminator=False)
 
if __name__ == "__main__":
    proj = angr.Project("test", load_options={'auto_load_libs':False})
    main = proj.loader.main_object.get_symbol("main")
    analyze(proj, main.rebased_addr, "test")
