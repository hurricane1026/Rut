from pathlib import Path
p=Path('/home/hurricane/private/code/Rut-s1/include/rut/runtime/callbacks_impl.h');s=p.read_text();needle='''            if (segmented_body && response_formatted) {
                const auto& body = cfg->response_bodies[outcome.response_body_idx - 1];
''';assert s.count(needle)==1
extra='''                // Experimental larger first burst before the remaining sendfile.
                if constexpr (requires(Loop* l) { l->pool.alloc_bulk(); }) {
                    constexpr u32 kFilePrefixCapacity = 64u * 1024u;
                    if (!conn.tls_active && body.file_fd() >= 0 &&
                        body.len >= 2u * kFilePrefixCapacity && !conn.send_armed &&
                        !conn.upstream_send_armed && conn.send_slice != nullptr &&
                        conn.send_buf.data() == conn.send_slice &&
                        conn.send_buf.capacity() < kFilePrefixCapacity &&
                        conn.send_buf.len() <= kFilePrefixCapacity) {
                        if (u8* expanded = loop->pool.alloc_bulk()) {
                            const u32 header_len = conn.send_buf.len();
                            __builtin_memcpy(expanded, conn.send_buf.data(), header_len);
                            u8* previous = conn.send_slice;
                            conn.send_slice = expanded;
                            conn.send_buf.bind(expanded, kFilePrefixCapacity);
                            conn.send_buf.commit(header_len);
                            loop->pool.free(previous);
                        }
                    }
                }
'''
p.write_text(s.replace(needle,needle+extra))
p=Path('/tmp/rut-bounded-followup-20260928/ebpf-tools/probe_static_large.py');s=p.read_text().replace("baseline=str(root/'ebpf-tools/rut-buffered-more')","baseline=str(root/'ebpf-tools/rut-small-poll-first')");p.with_name('probe_large_file_prefix64.py').write_text(s)
