require 'bpfql/query'

module Bpfql
  class DSL
    def initialize(qb)
      @builder = qb
      @_where_continue = false
    end
    attr_reader :builder

    def select(*members)
      builder.select = Query::SelectOption.new(members)
    end

    def from(probe)
      builder.from = Query::ProbeOption.new(probe)
    end

    def where(*filter, **options)
      builder.where = []
      builder.where << eval_where(*filter, **options)
      @_where_continue = true
    end

    def _and(*filter, **options)
      if @_where_continue
        builder.where << eval_where(*filter, **options)
      else
        raise ArgumentError, "Cannot invoke _and() before where()"
      end
    end

    def group_by(var)
      builder.group_by = var
    end

    def interval(timing)
      builder.interval = timing
    end

    def stop_after(timing)
      builder.stop = Query::StopOption.new(:after, timing)
    end

    private
    def eval_where(*filter, **options)
      case filter.size
      when 1
        if (options.keys & %i(is not lt gt lteq gteq)).empty?
          raise ArgumentError, "Invalid parameter: #{filter}, #{options}"
        end
        %i(is not lt gt lteq gteq).each do |ope|
          if options.has_key?(ope)
            return Query::FilterOption.new(filter[0], ope.to_s, options[ope])
          end
        end
      when 3
        return Query::FilterOption.new(*filter)
      else
        raise ArgumentError, "Invalid parameter: #{filter}, #{options}"
      end
    end
  end
end

def BPFQL(&b)
  query = Bpfql::Query.new
  evaluator = Bpfql::DSL.new(query)
  evaluator.instance_eval(&b)
  query
end
