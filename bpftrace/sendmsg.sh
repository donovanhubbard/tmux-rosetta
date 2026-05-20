#!/usr/bin/env bash

bpftrace -e '
#include <linux/uio.h>

tracepoint:syscalls:sys_enter_sendmsg

/comm == "tmux: server"/
{
    @dirty=1;
    $msg=(struct user_msghdr *)args->msg;
    $iov_arr=(struct iovec *)$msg->msg_iov;

    $vec = $iov_arr[0];
    @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);

    if($msg->msg_iovlen > 1){
      $vec = $iov_arr[1];
      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
    }
    if($msg->msg_iovlen > 2){
      $vec = $iov_arr[2];
      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
    }
    if($msg->msg_iovlen > 3){
      $vec = $iov_arr[3];
      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
    }
    if($msg->msg_iovlen > 4){
      printf("More than 4 iovecs. Cant print them all. count=%d",$msg->msg_iovlen );
      @data[pid, args.fd, nsecs] = buf($vec.iov_base, $vec.iov_len);
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

