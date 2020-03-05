require 'bpfql'

module Bpfql
  module Cli
    USAGE = <<~USAGE
      #{File.basename $0} version #{Bpfql::VERSION}
      usage:
      \t#{File.basename $0} <YAML_FILE>
    USAGE

    def self.run(argv)
      if argv.size != 1
        $stderr.puts USAGE
        exit 1
      end

      file = argv[0]
      q = nil
      case File.extname(file)
      when ".rb", ".bpfql"
        dsl = File.read(file)
        q = [eval(dsl)]
      when ".yml", ".yaml"
        q = Bpfql::Query.parse_yaml(File.read file)
      end

      r = Bpfql::Runner.new(q[0])
      r.run
    end
  end
end
