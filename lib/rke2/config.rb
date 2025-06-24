# Copyright (c) 2025 Kk
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# frozen_string_literal: true

require 'yaml'

# Config module
module RKE2
  # Config module
  module Config
    def self.load_config(config_file = 'config.yml')
      YAML.load_file(config_file)
    end
  end
end
