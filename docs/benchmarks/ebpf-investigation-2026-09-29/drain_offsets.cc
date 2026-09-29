#include "rut/runtime/connection_base.h"
extern "C" unsigned offset_drain(){return __builtin_offsetof(rut::ConnectionBase,upstream_recv_drain_offset);}
extern "C" unsigned offset_phase(){return __builtin_offsetof(rut::ConnectionBase,response_read_deadline_post_commit_phase);}
