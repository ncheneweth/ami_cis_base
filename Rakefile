require 'rubocop/rake_task'

desc 'Run Ruby style checks'
RuboCop::RakeTask.new(:style)

task :validate do
  system('bundle exec kitchen verify')
end

# assumes a box running with port forwarding on 2222
#task :vagrant do
#  system('bundle exec kitchen verify')
#end
# for now we're just validating - once we have Packer here we can add steps
task test: %w(style validate)
task default: %w(style validate)

begin
  require 'kitchen/rake_tasks'
  Kitchen::RakeTasks.new
rescue LoadError
  puts '>>>>> Kitchen gem not loaded, omitting tasks' unless ENV['CI']
end
