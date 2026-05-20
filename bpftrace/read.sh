#!/usr/bin/env bash

bpftrace -e '
#include <linux/uio.h>

tracepoint:syscalls:sys_enter_read
/comm == "tmux: server"/
{
    @dirty=1;
    @data[pid, args.fd, nsecs] = buf(args.buf, args.count);
}

tracepoint:syscalls:sys_enter_readv
/comm == "tmux: server"/
{
    @dirty=1;
    $iov_arr=(struct iovec *)args.vec;
    $vec = $iov_arr[0];
    @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);

    if(args.vlen > 1){
      $vec = $iov_arr[1];
      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
    }

    if(args.vlen > 2){
      $vec = $iov_arr[2];
      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
    }

    if(args.vlen > 3){
      $vec = $iov_arr[3];

      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
    }

    if(args.vlen > 4) {
        printf("More than 4 iovecs. Cant print them all. count=%d", args.vlen );
    }
}


interval:s:1
{
    if(@dirty>0){
	@dirty=0;
        print(@data);
        clear(@data);
    }
}
'


