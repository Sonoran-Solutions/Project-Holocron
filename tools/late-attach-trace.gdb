set confirm off
set pagination off
set debuginfod enabled off
handle SIGUSR1 nostop noprint pass
handle SIGABRT nostop noprint pass
target remote 127.0.0.1:27979

# `0x140454070` has just populated these locals at 0x14043cf98.  The filter
# and output retain envelope structure only, never the following login body.
break *0x14043cf98
condition 1 *(unsigned int *)($rsp + 0x58) == 0x011c5800
commands 1
  silent
  printf "envelope message=0x%x routeA=0x%x routeB=0x%x\n", *(unsigned int *)($rsp + 0x58), *(unsigned short *)($rsp + 0x30), *(unsigned short *)($rsp + 0xf8)
  continue
end

# At 0x1404347eb r14 is the resolved endpoint virtual target; r8d/r9d are
# the queued message and routeA.  This identifies the callback target without
# inspecting any application-body bytes.
break *0x1404347eb
condition 2 $r8d == 0x011c5800 && ($r9d & 0xffff) == 0xe800
commands 2
  silent
  printf "callback endpoint=%p message=0x%x routeA=0x%x\n", $r14, $r8d, $r9d
  continue
end

continue
