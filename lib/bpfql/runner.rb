require 'rbbcc'

module Bpfql
  # TODO: REFACTOR ME!!
  class Runner
    def initialize(qobj)
      @query_builder = qobj
    end

    def run
      @module = RbBCC::BCC.new(text: bpf_source)
      @start_ts = 0
      print_event = lambda { |cpu, data, size|
        event = @module["events"].event(data)
        @start_ts = event.ts if @start_ts == 0

        time_s = ((event.ts - @start_ts).to_f) / 1000000000
        puts("%-18.9f %-16s %-6d" % [time_s, event.comm, event.pid])
      }

      @module["events"].open_perf_buffer(&print_event)
      loop {
        begin
          @module.perf_buffer_poll()
        rescue Interrupt
          break
        end
      }
      puts "Exiting bpfql..."
    end

    def bpf_source
      <<~SOURCE
        #include <linux/sched.h>
        #define BPFQL_ARY_MAX 64
        #define BPFQL_STR_MAX 64
        #{data_struct_source}

        BPF_PERF_OUTPUT(events);

        #{trace_func_source}
      SOURCE
    end

    def data_struct_source
      <<~STRUCT
        struct data_t {
          #{tracepoint_fields.map{|k| field_maps[k] + ";"}.join("\n  ")}
        };
      STRUCT
    end

    def trace_func_source
      if qb.probe.tracepoint?
        src = <<~FUNCTION
          TRACEPOINT_PROBE(#{qb.probe.arg1}, #{qb.probe.arg2}) {
            struct data_t data = {};
            __ASSIGN_PID__
            __ASSIGN_TS__
            __ASSIGN_COMM__

            __ASSIGN_FIELDS__
            events.perf_submit(args, &data, sizeof(data));
            return 0;
          }
        FUNCTION
        src.sub!('__ASSIGN_PID__', tracepoint_fields.include?("pid") ? 'data.pid = bpf_get_current_pid_tgid();' : '')
        src.sub!('__ASSIGN_TS__', tracepoint_fields.include?("ts") ? 'data.ts = bpf_ktime_get_ns();' : '')
        src.sub!('__ASSIGN_COMM__', tracepoint_fields.include?("comm") ? 'bpf_get_current_comm(&data.comm, sizeof(data.comm));' : '')

        if (tracepoint_fields - %w(pid ts comm)).empty?
          src.sub!('__ASSIGN_FIELDS__', '')
        else
          assigner = (tracepoint_fields - %w(pid ts comm)).map { |field|
            "data.#{field} = args->#{field};"
          }.join("\n")
          src.sub!('__ASSIGN_FIELDS__', assigner)
        end
        src
      else
        raise NotImplementedError, "unsupported probe: #{qb.probe.to_s}"
      end
    end

    def tracepoint_fields
      @fields ||= begin
                    if qb.select.members[0] == '*'
                      field_maps.keys
                    else
                      qb.select.members
                    end
                  end
    end

    def tracepoint_field_maps_from_format
      @_fmt ||= begin
                  fmt = File.read "/sys/kernel/debug/tracing/events/#{qb.probe.arg1}/#{qb.probe.arg2}/format"
                  dst = {}
                  fmt.each_line do |l|
                    next unless l.include?("field:")
                    next if l.include?("common_")
                    kv = l.split(";").map{|elm| elm.split(":").map(&:strip)}.reject{|e| e.size != 2 }
                    kv = Hash[kv]
                    field_name = kv['field'].split.last
                    field_type = if kv['field'] =~ /^const char \* #{field_name}$/
                                   "char #{field_name}[BPFQL_STR_MAX]"
                                 elsif kv['field'] =~ /^const char \*const \* #{field_name}$/
                                   warn("not yet fully unsupported field type")
                                   "char #{field_name}[BPFQL_ARY_MAX][BPFQL_STR_MAX]"
                                 else
                                   kv['field']
                                 end
                    dst[field_name] = field_type
                  end
                  dst
                end
    end

    def field_maps
      {
        "pid"  => "u32 pid",
        "ts"   => "u64 ts",
        "comm" => "char comm[TASK_COMM_LEN]"
      }.merge(tracepoint_field_maps_from_format)
    end

    private
    def qb
      @query_builder
    end

  end
end
