require 'rubocop/rake_task'

desc 'Run Ruby style checks'
RuboCop::RakeTask.new(:style)

task :validate do
  dir = File.join(File.dirname(__FILE__))
  sh("bundle exec inspec check #{dir}")
end

# assumes a box running with port forwarding on 2222
task :vagrant do
  system('bundle exec inspec exec controls/ -t ssh://vagrant@localhost:2222 --password=vagrant --sudo --sudo_password=vagrant')
end

task test: %w(style vagrant validate)
task default: %w(style validate)

begin
  require 'kitchen/rake_tasks'
  Kitchen::RakeTasks.new
rescue LoadError
  puts '>>>>> Kitchen gem not loaded, omitting tasks' unless ENV['CI']
end
