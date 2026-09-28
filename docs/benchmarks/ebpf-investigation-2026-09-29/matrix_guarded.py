import sys
sys.path.insert(0,'/home/hurricane/private/code/Rut-s1/scripts/nginx_benchmark')
import matrix
original=matrix.run_cell
def run_cell(command,log):
 command[1]='/tmp/rut-bounded-followup-20260928/ebpf-tools/accept_buffered_more_guarded.py'
 return original(command,log)
matrix.run_cell=run_cell
sys.exit(matrix.main())
