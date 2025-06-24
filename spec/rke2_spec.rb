# frozen_string_literal: true

require 'spec_helper'

RSpec.describe RKE2 do
  it 'has a version number' do
    expect(RKE2::VERSION).not_to be nil
  end

  it 'has the expected version format' do
    expect(RKE2::VERSION).to match(/\d+\.\d+\.\d+/)
  end
end
