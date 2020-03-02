require 'yaml'

module Bpfql
  class Query
    def self.parse_yaml(yaml)
      data = YAML.parse(yaml)
      data['BPFQL'].map do |query|
        Query.new do |builder|
          builder.select = SelectOption.new(query['select'])
          builder.from = query['from']
          if query['where']
            builder.where = FilterOption.parse(query['where'])
          end
          builder.group_by = query['group_by'] # Accepts nil
          builder.interval = query['interval'] # Accepts nil
          if query['stop_after']
            builder.stop = StopOption.new(:after, query['stop_after'])
          end
        end
      end
    end

    def initialize(&b)
      b.call(self)
    end
    attr_accessor :select, :from, :where, :group_by, :interval, :stop

    class SelectOption < Struct.new(:members, :type)
      def initialize(query)
        case query
        when String, Symbol
          if query.include? ','
            self.members = query.split(',').map{|v| v.strip }
          else
            self.members = [query]
          end
        when Array
          self.members = query
        end
      end
    end

    class FilterOption < Struct.new(:lhs, :op, :rhs)
      def self.parse(where)
        where_list = Array(where)
        where_list.map do |whr|
          FilterOption.new(*whr)
        end
      end

      def initialize(lhs, op=nil, rhs=nil)
        unless op
          m = /^([^\s]+)\s+([^\s]+)\s+([^\s]+|"[^"]+"|'[^']+')$/.match(lhs)
          unless m
            raise "Failed to parse where clause: #{lhs}"
          end
          super(m[1], m[2], m[3])
        else
          super(lhs, op, rhs)
        end
      end
    end

    class StopOption < Struct.new(:timing, :seconds)
      def initialize(timing, secstr)
        seconds = 0
        m = /^(\d+)(\w+)?$/.match(secstr.to_s)
        unless m
          raise "Failed to parse stop option clause: #{secstr}"
        end
        case m[2]
        when nil, /^s.*/
          seconds = m[1].to_i
        when /^m.*/
          seconds = m[1].to_i * 60
        when /^h.*/
          seconds = m[1].to_i * 60 * 60
        end
        super(timing, seconds)
      end
    end
  end
end
