#!/usr/bin/python
#
# urandomread  Example of instrumenting a kernel function via kprobe.
#              For Linux, uses BCC, BPF. Embedded C.
#
# NOTE: The random:urandom_read tracepoint was removed in Linux 5.17.
#       This version uses a kprobe on urandom_read_iter instead.
#
# REQUIRES: Linux 5.17+ (urandom_read_iter)
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/uio.h>

int kprobe__urandom_read_iter(struct pt_regs *ctx, struct kiocb *kiocb,
                               struct iov_iter *iter) {
    // iter->count is the number of bytes requested
    bpf_trace_printk("%zu\\n", iter->count);
    return 0;
}
""")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "BYTES"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
