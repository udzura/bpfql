# BPFQL

eBPF query runner. Choose a format in:

* Ruby DSL
* YAML
* SQL-like query language (in the future)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'bpfql'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install bpfql

## Usage

```ruby
BPFQL do
  select "*"
  from "tracepoint:random:urandom_read"
  where "comm", is: "ruby"
  _and  "pid", is: 12345
end
```

```ruby
BPFQL do
  select "count()"
  from "tracepoint:syscalls:sys_clone_enter"
  group_by "comm"
  interval "15s"
end
```

### YAML format

```yaml
BPFQL:
- select: count()
  from: tracepoint:syscalls:sys_clone_enter
  group_by: comm
  stop_after: "30s"
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/udzura/bpfql.

