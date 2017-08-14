control "docker_deamon_is_installed" do
  title "ensure docker is installed - not running yet"
  desc  "Ensure that the docker deamon is installed and enabled"
  impact 1.0
  describe service('docker') do
    it { should be_installed }
    it { should be_enabled }
    # it { should be_running }
  end
end
control "1.5 Audit docker daemon" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/usr\/bin\/docker\s*\-k\s*docker/) }
  end
end

control "1.6 Audit var/lib/docker" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/var\/lib\/docker\s*\-k\s*docker/) }
  end
end

control "1.7 Audit Docker files and directories - /etc/docker (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/etc\/docker\s*\-k\s*docker/) }
  end
end

control "1.8 Audit Docker files and directories - docker.service (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/lib\/systemd\/system\/docker\.service\s*\-k\s*docker/) }
  end
end

control "1.9 Audit Docker files and directories - docker.socket (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/lib\/systemd\/system\/docker\.socket\s*\-k\s*docker/) }
  end
end

control "1.10 Audit Docker files and directories - /etc/default/docker (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/etc\/default\/docker\s*\-k\s*docker/) }
  end
end


control "1.11 Audit Docker files and directories - /etc/docker/daemon.json (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/etc\/docker\/docker\.json\s*\-k\s*docker/) }
  end
end

control "1.12 Audit Docker files and directories - /usr/bin/docker-containerd (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/usr\/bin\/docker-containerd\s*\-k\s*docker/) }
  end
end

control "1.13 Audit Docker files and directories - /usr/bin/docker-runc (Scored)" do
  title "Ensure docker deamon is audited"
  desc  "Apart from auditing your regular Linux file system and system calls, audit Docker daemon as well. Docker daemon runs with 'root' privileges. It is thus necessary to audit its activities and usage."
  impact 1.0
  describe file("/etc/audit/audit.rules") do
    its("content") { should match(/\-w\s*\/usr\/bin\/docker-runc\s*\-k\s*docker/) }
  end
end

control "3.1 Verify that docker.service file ownership is set to root:root (Scored)" do
  title "Ensure docker.service file ownership is root"
  desc  "'docker.service' file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should be owned and group-owned by 'root' to maintain the integrity of the file."
  impact 1.0
  describe file("/lib/systemd/system/docker.service") do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root'}
  end
end

control "3.2 Verify that docker.service file mode is 644 (Scored)" do
  title "Ensure docker.service file ownership is root"
  desc  "'docker.service' file contains sensitive parameters that may alter the behavior of Docker daemon. Hence, it should be owned and group-owned by 'root' to maintain the integrity of the file."
  impact 1.0
  describe file("/lib/systemd/system/docker.service") do
    its('mode') { should cmp '0644' }
  end
end
