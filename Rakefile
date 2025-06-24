# frozen_string_literal: true

# Copyright (c) 2025 kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'yard'

# Default task
task default: %i[spec rubocop]

# RSpec test task
RSpec::Core::RakeTask.new(:spec)

# RuboCop tasks
begin
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new

  desc 'Run RuboCop with auto-correct'
  task 'rubocop:auto_correct' do
    sh 'bundle exec rubocop -A'
  end
rescue LoadError
  # RuboCop not available
end

# YARD documentation task
begin
  YARD::Rake::YardocTask.new do |t|
    t.files   = ['lib/**/*.rb']
    t.options = ['--no-private']
  end
rescue LoadError
  # YARD not available
end

# Quality tasks
desc 'Run all quality checks'
task quality: %i[spec rubocop]

# Development tasks
desc 'Install development dependencies'
task :setup do
  sh 'bundle install'
  puts '✅ Development environment setup complete!'
end

desc 'Clean up generated files'
task :clean do
  sh 'rm -rf pkg/'
  sh 'rm -rf tmp/'
  sh 'rm -rf coverage/'
  sh 'rm -rf doc/'
  puts '🧹 Cleanup complete!'
end

desc 'Run the CLI tool'
task :run do
  sh 'ruby -Ilib bin/rke2'
end

desc 'Run interactive Ruby session with the library loaded'
task :console do
  sh 'bundle exec irb -Ilib -rrke2'
end

# Build and release tasks
desc 'Build and install gem locally'
task :install_local do
  sh 'gem build rke2.gemspec'
  sh 'gem install rke2-*.gem'
  sh 'rm rke2-*.gem'
  puts '💎 Gem installed locally!'
end

# Git workflow tasks (keep the original push task)
desc 'Quick git add, commit, pull and push'
task :push do
  require 'time'
  system 'git add .'
  system "git commit -m 'Update #{Time.now}.'"
  system 'git pull'
  system 'git push origin main'
end

desc 'Show project statistics'
task :stats do
  puts '📊 Project Statistics:'
  puts 'Lines of code:'
  sh "find lib -name '*.rb' | xargs wc -l | tail -1"
  puts "\nFiles:"
  sh "find lib -name '*.rb' | wc -l"
  puts "\nTests:"
  sh "find spec -name '*.rb' 2>/dev/null | wc -l || echo '0'"
end
