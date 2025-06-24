# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

module RKE2
  class Error < StandardError; end
  # Your code goes here...
end

Dir.glob(File.join(File.dirname(__FILE__), 'rke2/*.rb')).each do |r|
  require_relative "rke2/#{File.basename(r, '.rb')}"
end
