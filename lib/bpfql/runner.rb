require 'rbbcc'

module Bpfql
  # TODO: REFACTOR ME!!
  class Runner
    def initialize(qobj)
      @query_builder = qobj
      @fmt = gen_fmt
      @start_ts = 0
    end

    def run
      $stderr.puts bpf_source if ENV['BPFQL_DEBUG']
      @module = RbBCC::BCC.new(text: bpf_source)
      puts(@fmt.gsub(/(\.\d+f|d)/, 's') % tracepoint_fields_sorted.map(&:upcase))

      @module["events"].open_perf_buffer do |cpu, data, size|
        event = @module["events"].event(data)
        puts(@fmt % gen_extract_data(event))
      end
      loop {
        begin
          @module.perf_buffer_poll()
        rescue Interrupt
          break
        end
      }
      puts "Exiting bpfql..."
    end

    def gen_fmt
      fmt = []
      fmt << '%-18.9f' if tracepoint_fields.include?("ts")
      fmt << '%-16s' if tracepoint_fields.include?("comm")
      fmt << '%-6d' if tracepoint_fields.include?("pid")
      fields_noncommon.each do |f|
        if field_maps[f] =~ /^char \w+\[\w+\]$/
          fmt << '%-16s'
        else
          fmt << '%-8d'
        end
      end
      fmt.join ' '
    end

    def gen_extract_data(event)
      ret = []
      if tracepoint_fields.include?("ts")
        @start_ts = event.ts if @start_ts == 0
        time_s = ((event.ts - @start_ts).to_f) / 1000000000
        ret << time_s
      end

      tracepoint_fields_sorted.each do |f|
        next if f == 'ts'
        ret << event.send(f)
      end
      ret
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

            __FILTER__
              events.perf_submit(args, &data, sizeof(data));
            __FILTER_END__
            return 0;
          }
        FUNCTION
        src.sub!('__ASSIGN_PID__', tracepoint_fields.include?("pid") ? 'data.pid = bpf_get_current_pid_tgid();' : '')
        src.sub!('__ASSIGN_TS__', tracepoint_fields.include?("ts") ? 'data.ts = bpf_ktime_get_ns();' : '')
        src.sub!('__ASSIGN_COMM__', tracepoint_fields.include?("comm") ? 'bpf_get_current_comm(&data.comm, sizeof(data.comm));' : '')

        if fields_noncommon.empty?
          src.sub!('__ASSIGN_FIELDS__', '')
        else
          assigner = fields_noncommon.map { |field|
            "data.#{field} = args->#{field};"
          }.join("\n")
          src.sub!('__ASSIGN_FIELDS__', assigner)
        end

        if qb.where && !qb.where.empty?
          src.sub!('__FILTER__', filter_clause)
          src.sub!('__FILTER_END__', filter_end_clause)
        else
          src.sub!('__FILTER__', "")
          src.sub!('__FILTER_END__', "")
        end
        src
      else
        raise NotImplementedError, "unsupported probe: #{qb.probe.to_s}"
      end
    end

    def filter_clause
      conds = []
      needle_section = ""
      qb.where.each do |filter|
        if filter[0] == "comm" # || field_maps[filter[0]] =~ /^const char \* #{filter[0]}$/
          ope = case filter[1].to_s
                when "is"; ""
                when "not"; "!"
                else
                  raise "String comparation supports only == or !=; You put: #{filter}"
                end
          filter_string = %Q<"#{filter[2]}">
          needle_section = <<~NEEDLE
            bool matched   = true;
            char needle[] = #{filter_string};
            char haystack[sizeof(needle)] = {};
            bpf_probe_read(&haystack, sizeof(haystack), (void*)data.#{filter[0]});
            for (int i = 0; i < sizeof(needle) - 1; ++i) {
              if (needle[i] != haystack[i]) {
                matched = false;
              }
            }
          NEEDLE
          conds << %Q<#{ope}matched>
        else
          lhs = "data.#{filter[0]}"
          ope = case filter[1].to_s
                when "is"; "=="
                when "not"; "!="
                when "lt"; "<"
                when "gt"; ">"
                when "lteq"; "<="
                when "gteq"; ">="
                else
                  raise "[BPFQL BUG] Cannot evaluate ope: #{filter}; This may be a bug"
                end
          rhs = filter[2]
        conds << [lhs, ope, rhs].join(" ")
        end
      end
      return <<~FILTER
        #{needle_section}
        if (#{conds.join("&&")}) {
      FILTER
    end

    def filter_end_clause
      return "}"
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

    def tracepoint_fields_sorted
      [].tap do |a|
        a << 'ts' if tracepoint_fields.include?("ts")
        a << 'comm' if tracepoint_fields.include?("comm")
        a << 'pid' if tracepoint_fields.include?("pid")
        a.concat fields_noncommon
      end
    end

    def fields_noncommon
      tracepoint_fields - %w(pid ts comm)
    end

    def tracepoint_field_maps_from_format
      @_tfmap ||= begin
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
