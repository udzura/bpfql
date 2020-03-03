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

      yaml_file = argv[0]
      q = Bpfql::Query.parse_yaml(File.read yaml_file)
      r = Bpfql::Runner.new(q[0])
      r.run
    end
  end
end
