BPFQL do
  select "ts", "comm", "pid", "__syscall_nr", "ret"
  from "tracepoint:syscalls:sys_exit_read"
  # where "comm" is: "ruby"
end
