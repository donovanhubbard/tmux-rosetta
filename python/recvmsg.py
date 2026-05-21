#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import argparse
import sys

MAX_MSG_SIZE = 4096
MAX_IOVEC    = 8

parser = argparse.ArgumentParser(description="Trace recvmsg syscalls")
parser.add_argument("-p", "--pid",    type=int, default=0,            help="trace this PID only")
parser.add_argument("-o", "--output", type=str, default="recvmsg.bin", help="file to write iovec binary data")
args = parser.parse_args()

cflags = [
    "-DTARGET_PID=%d"   % args.pid,
    "-DMAX_MSG_SIZE=%d" % MAX_MSG_SIZE,
    "-DMAX_IOVEC=%d"    % MAX_IOVEC,
]

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <uapi/linux/uio.h>

struct entry_t {
    int fd;
    u64 msg;
};

struct data_t {
    u32 pid;
    int fd;
    u32 iov_idx;
    u32 data_len;
    char comm[TASK_COMM_LEN];
    u8 data[MAX_MSG_SIZE];
};

BPF_HASH(entry_map, u64, struct entry_t);
BPF_PERCPU_ARRAY(data_heap, struct data_t, 1);
BPF_PERF_OUTPUT(events);

int trace_enter(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (TARGET_PID != 0 && pid != TARGET_PID)
        return 0;

    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1(ctx);

    struct entry_t entry = {};
    bpf_probe_read_kernel(&entry.fd,  sizeof(entry.fd),  &regs->di);
    bpf_probe_read_kernel(&entry.msg, sizeof(entry.msg), &regs->si);

    u64 tid = bpf_get_current_pid_tgid();
    entry_map.update(&tid, &entry);
    return 0;
}

int trace_exit(struct pt_regs *ctx) {
    u64 tid = bpf_get_current_pid_tgid();

    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        entry_map.delete(&tid);
        return 0;
    }

    struct entry_t *entry = entry_map.lookup(&tid);
    if (!entry) return 0;

    struct user_msghdr msghdr = {};
    bpf_probe_read_user(&msghdr, sizeof(msghdr), (void *)entry->msg);

    int zero = 0;
    u32 pid = tid >> 32;

    #pragma unroll
    for (int i = 0; i < MAX_IOVEC; i++) {
        if (i >= msghdr.msg_iovlen) continue;

        struct iovec iov = {};
        bpf_probe_read_user(&iov, sizeof(iov), &msghdr.msg_iov[i]);

        if (!iov.iov_base || !iov.iov_len) continue;

        struct data_t *data = data_heap.lookup(&zero);
        if (!data) continue;

        data->pid     = pid;
        data->fd      = entry->fd;
        data->iov_idx = i;
        bpf_get_current_comm(&data->comm, sizeof(data->comm));
        data->data_len = iov.iov_len < MAX_MSG_SIZE ? iov.iov_len : MAX_MSG_SIZE;
        bpf_probe_read_user(data->data, MAX_MSG_SIZE, iov.iov_base);

        events.perf_submit(ctx, data, sizeof(*data));
    }

    entry_map.delete(&tid);
    return 0;
}
""", cflags=cflags)

b.attach_kprobe(event=b.get_syscall_fnname("recvmsg"),    fn_name="trace_enter")
b.attach_kretprobe(event=b.get_syscall_fnname("recvmsg"), fn_name="trace_exit")

outfile = open(args.output, "wb")

def print_event(cpu, raw_data, size):
    event = b["events"].event(raw_data)
    print("pid=%-6d comm=%-16s fd=%d" % (
        event.pid,
        event.comm.decode("utf-8", "replace"),
        event.fd,
    ))
    outfile.write(bytes(event.data[:event.data_len]))
    outfile.flush()

b["events"].open_perf_buffer(print_event)
print("Tracing recvmsg, writing iovec data to %s... Ctrl-C to stop." % args.output, file=sys.stderr)
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
finally:
    outfile.close()
