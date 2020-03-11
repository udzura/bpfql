BPFQL do
  select "*"
  from "tracepoint:random:urandom_read"
  where "comm", is: "ruby"
end

