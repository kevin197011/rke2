# frozen_string_literal: true

source 'https://rubygems.org'

# Specify your gem's dependencies in rke2.gemspec
gemspec

# Additional development gems not specified in gemspec
group :development, :test do
  # Debugging tools
  gem 'pry', '~> 0.14', require: false
  gem 'pry-byebug', '~> 3.10', require: false, platforms: [:mri]

  # Interactive Ruby shell
  gem 'irb'
end

# Performance profiling gems for development
group :development do
  gem 'benchmark-ips', '~> 2.10', require: false
  gem 'memory_profiler', '~> 1.0', require: false
end
