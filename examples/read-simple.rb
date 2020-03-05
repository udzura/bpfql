BPFQL do
  select "ts", "comm", "pid", "__syscall_nr", "ret"
  from "tracepoint:syscalls:sys_exit_read"
  if ENV['TARGET_COMM']
    where "comm", is: ENV['TARGET_COMM']
  elsif ENV['TARGET_PID']
    where "pid", is: ENV['TARGET_PID']
  end
end
