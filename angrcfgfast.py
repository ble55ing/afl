# -*- coding: utf-8 -*-  
import angr
import claripy
from angrutils import *
 
def main():
    proj = angr.Project('./test1',load_options={"auto_load_libs":False})
    print("----------static-----------")
    cfgs = proj.analyses.CFGFast()
    vis = AngrVisFactory().default_cfg_pipeline(cfgs, asminst=True, vexinst=False)
    vis.set_output(DotOutput("test1", format="dot"))
    vis.process(cfgs.graph)
    #plot_cfg(cfgs, "static", asminst=True, remove_imports=True, remove_path_terminator=True)# too big
    print("This is the graph:", cfgs.graph)
    print("It has %d nodes and %d edges" % (len(cfgs.graph.nodes()), len(cfgs.graph.edges())))
    print("###-entry node-###")
    entry_node = cfgs.get_any_node(proj.entry)
    print("There were %d contexts for the entry block" % len(cfgs.get_all_nodes(proj.entry)))
    print("###-father node-###")
    print("Predecessors of the entry point:", entry_node.predecessors)
    print("###-son node-###")
    print("Successors of the entry point:", entry_node.successors)
    print entry_node.block
    #print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfgs.get_successors_and_jumpkind(entry_node) ])
 
 
'''
    print("----------dynamic----------")
    cfgd = proj.analyses.CFGAccurate(keep_state=True)
    print("This is the graph:", cfgd.graph)
    print("It has %d nodes and %d edges" % (len(cfgd.graph.nodes()), len(cfgd.graph.edges())))
    print("###-entry node-###")
    entry_node = cfgd.get_any_node(proj.entry)
    print("There were %d contexts for the entry block" % len(cfgd.get_all_nodes(proj.entry)))
    print("###-father node-###")
    print("Predecessors of the entry point:", entry_node.predecessors)
    print("###-son node-###")
    print("Successors of the entry point:", entry_node.successors)
    print("Successors (and type of jump) of the entry point:", [ jumpkind + " to " + str(node.addr) for node,jumpkind in cfgd.get_successors_and_jumpkind(entry_node) ])
'''
if __name__ == "__main__":
    main()

