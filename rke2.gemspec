# frozen_string_literal: true

require_relative 'lib/rke2/version'

Gem::Specification.new do |spec|
  spec.name = 'rke2'
  spec.version = RKE2::VERSION
  spec.authors = ['Kk']
  spec.email = ['kk@example.com']

  spec.summary = 'RKE2 Kubernetes 集群自动化部署工具'
  spec.description = '一个功能完整的 RKE2 Kubernetes 集群自动化部署和管理工具，采用模块化架构设计，支持完整的集群生命周期管理。'
  spec.homepage = 'https://github.com/kevin197011/rke2'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 2.7.0'

  # Metadata
  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/kevin197011/rke2'
  spec.metadata['changelog_uri'] = 'https://github.com/kevin197011/rke2/blob/main/CHANGELOG.md'
  spec.metadata['documentation_uri'] = 'https://github.com/kevin197011/rke2/blob/main/README.md'
  spec.metadata['bug_tracker_uri'] = 'https://github.com/kevin197011/rke2/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end

  spec.bindir = 'bin'
  spec.executables = ['rke2']
  spec.require_paths = ['lib']

  # Core dependencies
  spec.add_dependency 'net-scp', '~> 4.0'
  spec.add_dependency 'net-ssh', '~> 7.0'

  # Development dependencies
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop', '~> 1.50'
  spec.add_development_dependency 'rubocop-rspec', '~> 2.20'
  spec.add_development_dependency 'yard', '~> 0.9'
end
