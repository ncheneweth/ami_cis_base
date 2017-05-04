require 'English'
require_relative 'defaults'
# skip test run if target server is not rhel
only_if { os[:family] == 'redhat' }
# skip test run unless the desired cis published version is 1 (default=2)
only_if { (ENV['CIS_VERSION'] || DEFAULT_CIS_VERSION) == 1 }

# Environment attributes used to override defaults
level_two_enabled = (ENV['CIS_PROFILE_LEVEL'] || DEFAULT_CIS_PROFILE_LEVEL) >= 2 # default is level 2
ipv6_disabled = (ENV['CIS_IPV6_STATE'] || DEFAULT_CIS_IPV6_DISABLED) # default is true

title '1 Install Updates, Patches and Additional Security Software'
title '1.1 Filesystem Configuration'

control '1.1.1 Create Separate Partition for /tmp' do
  title 'Create Separate Partition for /tmp (Scored)'
  desc 'The /tmp directory is a world-writable directory used for temporary storage by all users and some applications.'
  impact 1.0
  describe mount('/tmp') do
    it { should be_mounted }
  end
  tag remediation: 'http://tldp.org/HOWTO/LVM-HOWTO/'
end

control '1.1.2 Set nodev option for /tmp Partition' do
  title 'Set nodev option for /tmp Partition (Scored)'
  desc 'The nodev mount option specifies that the filesystem cannot contain special devices.'
  impact 1.0
  describe mount('/tmp') do
    its('options') { should include 'nodev' }
  end
end

control '1.1.3 Set nosuid option for /tmp Partition' do
  title 'Set nosuid option for /tmp Partition (Scored)'
  desc 'The nosuid mount option specifies that the filesystem cannot contain set userid files.'
  impact 1.0
  describe mount('/tmp') do
    its('options') { should include 'nosuid' }
  end
end

control '1.1.4 Set noexec option for /tmp Partition' do
  title 'Set noexec option for /tmp Partition (Scored)'
  desc  'The noexec mount option specifies that the filesystem cannot contain executable binaries.'
  impact 1.0
  describe mount('/tmp') do
    its('options') { should include 'noexec' }
  end
end

control '.1.5 Create Separate Partition for /var' do
  title 'Create Separate Partition for /var (Scored)'
  desc  'The /var directory is used by daemons and other system services to temporarily store dynamic data. Some directories created by these processes may be world-writable.'
  impact 1.0
  describe mount('/var') do
    it { should be_mounted }
  end
  tag remediation: 'http://tldp.org/HOWTO/LVM-HOWTO/'
end

control '1.1.6 Bind Mount the /var/tmp directory to /tmp' do
  title 'Bind Mount the /var/tmp directory to /tmp (Scored)'
  desc  'The /var/tmp directory is normally a standalone directory in the /var file system. Binding /var/tmp to /tmp establishes an unbreakable link to /tmp that cannot be removed (even by the root user). It also allows /var/tmp to inherit the same mount options that /tmp owns, allowing /var/tmp to be protected in the same /tmp is protected. It will also prevent /var from filling up with temporary files as the contents of /var/tmp will actually reside in the file system containing /tmp.'
  impact 1.0
  describe file('/etc/fstab') do
    its('content') { should match %r{/$\s*\/tmp\s+\/var\/tmp\s+none\s+bind\s+0\s+0\s*$/} }
  end
end

control '1.1.7 Create Separate Partition for /var/log' do
  title 'Create Separate Partition for /var/log (Scored)'
  desc  'The /var/log directory is used by system services to store log data.'
  impact 1.0
  describe mount('/var/log') do
    it { should be_mounted }
  end
  tag remediation: 'http://tldp.org/HOWTO/LVM-HOWTO/'
end

control '1.1.8 Create Separate Partition for /var/log/audit' do
  title 'Create Separate Partition for /var/log/audit (Scored)'
  desc  'The auditing daemon, auditd, stores log data in the /var/log/audit directory.'
  impact 1.0
  describe mount('/var/log/audit') do
    it { should be_mounted }
  end
  tag remediation: 'http://tldp.org/HOWTO/LVM-HOWTO/'
end

control '1.1.9 Create Separate Partition for /home' do
  title 'Create Separate Partition for /home (Scored)'
  desc  'The /home directory is used to support disk storage needs of local users.'
  impact 1.0
  describe mount('/home') do
    it { should be_mounted }
  end
  tag remediation: 'http://tldp.org/HOWTO/LVM-HOWTO/'
end

control '1.1.10 Add nodev Option to home' do
  title 'Add nodev Option to /home (Scored)'
  desc  'When set on a file system, this option prevents character and block special devices from being defined, or if they exist, from being used as character and block special devices.'
  impact 1.0
  describe mount('/home') do
    its('options') { should include 'nodev' }
  end
end

control '1.1.11 Add nodev Option to Removable Media Partitions' do
  title 'Add nodev Option to Removable Media Partitions (Not Scored)'
  desc  'Set nodev on removable media to prevent character and block special devices that are present on the removable be treated as these device files.'
  impact 0.0
end

control '1.1.12 Add noexec Option to Removable Media Partitions' do
  title 'Add noexec Option to Removable Media Partitions (Not Scored)'
  desc  'Set noexec on removable media to prevent programs from executing from the removable media.'
  impact 0.0
end

control '1.1.13 Add nosuid Option to Removable Media Partitions' do
  title 'Add nosuid Option to Removable Media Partitions (Not Scored)'
  desc  'Set nosuid on removable media to prevent setuid and setgid executable files that are on that media from being executed as setuid and setgid.'
  impact 0.0
end

control '1.1.14 Add nodev Option to /dev/shm Partition' do
  title 'Add nodev Option to /dev/shm Partition (Scored)'
  desc  'The nodev mount option specifies that the /dev/shm (temporary filesystem stored in memory) cannot contain block or character special devices.'
  impact 1.0
  describe mount('/dev/shm') do
    it { should be_mounted }
  end
  describe mount('/dev/shm') do
    its('options') { should include 'nodev' }
  end
end

control '1.1.15 Add nosuid Option to /dev/shm Partition' do
  title 'Add nosuid Option to /dev/shm Partition (Scored)'
  desc  'The nosuid mount option specifies that the /dev/shm (temporary filesystem stored in memory) will not execute setuid and setgid on executable programs as such, but rather execute them with the uid and gid of the user executing the program.'
  impact 1.0
  describe mount('/dev/shm') do
    its('options') { should include 'nosuid' }
  end
end

control '1.1.16 Add noexec Option to /dev/shm Partition' do
  title 'Add noexec Option to /dev/shm Partition'
  desc  'Set noexec on the shared memory partition to prevent programs from executing from there.'
  impact 1.0
  describe mount('/dev/shm') do
    its('options') { should include 'noexec' }
  end
end

control '1.1.17 Set Sticky Bit on All World-Writable Directories' do
  title 'Set Sticky Bit on All World-Writable Directories (Scored)'
  desc  'Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.'
  impact 1.0
  describe command('find / -type d -perm -00002 \\! -perm -01000') do
    its('stdout') { should be_empty }
  end
end

if level_two_enabled
  control '1.1.18 Disable Mounting of cramfs Filesystems' do
    title 'Disable Mounting of cramfs Filesystems (Not Scored)'
    desc  'The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A cramfs image can be used without having to first decompress the image.'
    impact 0.0
    describe command('/sbin/lsmod | grep cramfs') do
      its('stdout') { should be_empty }
    end
  end

  control '1.1.19 Disable Mounting of freevxfs Filesystems' do
    title 'Disable Mounting of freevxfs Filesystems (Not Scored)'
    desc  'The freevxfs filesystem type is a free version of the Veritas type filesystem. This is the primary filesystem type for HP-UX operating systems.'
    impact 0.0
    describe command('/sbin/lsmod | grep freevxfs') do
      its('stdout') { should be_empty }
    end
  end

  control '1.1.20 Disable Mounting of jffs2 Filesystems' do
    title 'Disable Mounting of jffs2 Filesystems (Not Scored)'
    desc  'The jffs2 (journaling flash filesystem 2) filesystem type is a log-structured filesystem used in flash memory devices.'
    impact 0.0
    describe command('/sbin/lsmod | grep jffs2') do
      its('stdout') { should be_empty }
    end
  end

  control '1.1.21 Disable Mounting of hfs Filesystems' do
    title 'Disable Mounting of hfs Filesystems (Not Scored)'
    desc  'The hfs filesystem type is a hierarchical filesystem that allows you to mount Mac OS filesystems.'
    impact 0.0
    describe command('/sbin/lsmod | grep hfs') do
      its('stdout') { should be_empty }
    end
  end

  control '1.1.22 Disable Mounting of hfsplus Filesystems' do
    title 'Disable Mounting of hfsplus Filesystems (Not Scored)'
    desc  'The hfsplus filesystem type is a hierarchical filesystem designed to replace hfs that allows you to mount Mac OS filesystems.'
    impact 0.0
    describe command('/sbin/lsmod | grep hfsplus') do
      its('stdout') { should be_empty }
    end
  end

  control '1.1.23 Disable Mounting of squashfs Filesystems' do
    title 'Disable Mounting of squashfs Filesystems (Not Scored)'
    desc  'The squashfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems (similar to cramfs). A squashfs image can be used without having to first decompress the image.'
    impact 0.0
    describe command('/sbin/lsmod | grep squashfs') do
      its('stdout') { should be_empty }
    end
  end

  control '1.1.24 Disable Mounting of udf Filesystems' do
    title 'Disable Mounting of udf Filesystems (Not Scored)'
    desc  'The udf filesystem type is the universal disk format used to implement ISO/IEC 13346 and ECMA-167 specifications. This is an open vendor filesystem type for data storage on a broad range of media. This filesystem type is necessary to support writing DVDs and newer optical disc formats.'
    impact 0.0
    describe command('/sbin/lsmod | grep udf') do
      its('stdout') { should be_empty }
    end
  end
end

title '1.2 Configure Software Updates'

control '1.2.1 Configure Connection to the RHN RPM Repositories' do
  title 'Configure Connection to the RHN RPM Repositories (Not Scored)'
  desc  'Systems need to be registered with the Red Hat Network (RHN) to receive patch updates.'
  impact 1.0
  describe command('subscription-manager refresh') do
    its('stdout') { should match 'refreshed' }
  end
end

control '1.2.2 Verify Red Hat GPG Key is Installed' do
  title 'Verify Red Hat GPG Key is Installed (Scored)'
  desc  'Red Hat cryptographically signs updates with a GPG key to verify that they are valid.'
  impact 1.0
  describe package('gpg-pubkey') do
    it { should be_installed }
  end
  tag remediation: 'https://access.redhat.com/security/team/key'
end

control '1.2.3 Verify that gpgcheck is Globally Activated' do
  title 'Verify that gpgcheck is Globally Activated (Scored)'
  desc  "The gpgcheck option, found in the main section of the /etc/yum.conf file determines if an RPM package's signature is always checked prior to its installation."
  impact 0.0
  describe file('/etc/yum.conf') do
    its('content') { should match 'gpgcheck=1' }
  end
end

control '1.2.4 Disable the rhnsd Daemon' do
  title 'Disable the rhnsd Daemon (Not Scored)'
  desc  'The rhnsd daemon polls the Red Hat Network web site for scheduled actions and, if there are, executes those actions.'
  impact 0.0
  describe command('systemctl is-enabled rhnsd') do
    its('stdout') { should match 'disabled' }
  end
end if level_two_enabled

control '1.2.5 Obtain Software Package Updates with yum' do
  title 'Obtain Software Package Updates with yum (Not Scored)'
  desc  'The yum update utility performs software updates, including dependency analysis, based on repository metadata'
  impact 1.0
  describe command('yum check-update') do
    its('exit_status') { should be_zero }
  end
end

control '1.2.6 Verify Package Integrity Using RPM' do
  title 'Verify Package Integrity Using RPM (Not Scored)'
  desc  'RPM has the capability of verifying installed packages by comparing the installed files against the file information stored in the package.'
  impact 0.0
end

title '1.3 Advanced Intrusion Detection Environment (AIDE)'

if level_two_enabled
  control '1.3.1Install AIDE' do
    title 'Install AIDE (Scored)'
    desc  'In some installations, AIDE is not installed automatically.'
    impact 1.0
    describe package('aide') do
      it { should be_installed }
    end
  end

  control '1.3.2 Implement Periodic Execution of File Integrity' do
    title 'Implement Periodic Execution of File Integrity (Scored)'
    desc  'Implement periodic file checking, in compliance with site policy.'
    impact 1.0
    describe command('crontab -u root -l | grep aide') do
      its('stdout') { should match '/usr/sbin/aide/' }
    end
  end
end

title '1.4 Configure SELinux'

if level_two_enabled
  control '1.4.1 Ensure SELinux is not disabled in /boot/grub2/grub.cfg' do
    title 'Ensure SELinux is not disabled in /boot/grub2/grub.cfg (Scored)'
    desc  'Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters'
    impact 1.0
    describe file('/boot/grub2/grub.cfg') do
      it { should be_file }
    end
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should_not match 'selinux=0' }
    end
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should_not match 'enforcing=0' }
    end
    tag remediation: 'http://docs.fedoraproject.org/selinux-user-guide'
  end

  control '1.4.2 Set the SELinux State' do
    title 'Set the SELinux State (Scored)'
    desc  'Set SELinux to enable when the system is booted.'
    impact 1.0
    describe file('/etc/selinux/config') do
      its('content') { should match 'SELINUX=enforcing' }
    end
    describe command('/usr/sbin/sestatus') do
      its('stdout') { should match 'SELinux status: enabled' }
      its('stdout') { should match 'Current mode: enforcing' }
      its('stdout') { should match 'Mode from config file: enforcing' }
    end
  end

  control '1.4.3 Set the SELinux Policy' do
    title 'Set the SELinux Policy (Scored)'
    desc  'Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.'
    impact 1.0
    describe file('/etc/selinux/config') do
      its('content') { should match %r{/^SELINUXTYPE=(targeted|strict|mls)$/} }
    end
  end

  control '1.4.4 Remove SETroubleshoot' do
    title 'Remove SETroubleshoot (Scored)'
    desc  'The SETroubleshoot service notifies desktop users of SELinux denials through a user-friendly interface. The service provides important information around configuration errors, unauthorized intrusions, and other potential errors.'
    impact 1.0
    describe package('setroubleshoot') do
      it { should_not be_installed }
    end
  end

  control '1.4.5 Remove MCS Translation Service mcstrans' do
    title 'Remove MCS Translation Service (mcstrans) (Scored)'
    desc  'The mcstransd daemon provides category label information to client processes requesting information. The label translations are defined in /etc/selinux/targeted/setrans.conf'
    impact 1.0
    describe package('mcstrans') do
      it { should_not be_installed }
    end
  end

  control '1.4.6 Check for Unconfined Daemons' do
    title 'Check for Unconfined Daemons (Scored)'
    desc  'Daemons that are not defined in SELinux policy will inherit the security context of their parent process.'
    impact 1.0
    describe command("sudo ps -eZ | egrep 'initrc' | egrep -vw 'tr|ps|egrep|bash|awk' | tr ':' ' ' | awk '{ print $NF }'") do
      its('stdout') { should be_empty }
    end
  end
end

title '1.5 Secure Boot Settings'

control '1.5.1 Set UserGroup Owner on /boot/grub2/grub.cfg' do
  title 'Set User/Group Owner on /boot/grub2/grub.cfg (Scored)'
  desc  'Set the owner and group of /boot/grub2/grub.cfg to the root user.'
  impact 1.0
  describe file('/boot/grub2/grub.cfg') do
    it { should exist }
  end
  describe file('/boot/grub2/grub.cfg') do
    its('gid') { should cmp 0 }
  end
  describe file('/boot/grub2/grub.cfg') do
    its('uid') { should cmp 0 }
  end
end

control '1.5.2 Set Permissions on /boot/grub2/grub.cfg' do
  title 'Set Permissions on /boot/grub2/grub.cfg (Scored)'
  desc  'Set permission on the /boot/grub2/grub.cfg file to read and write for root only.'
  impact 1.0
  describe file('/boot/grub2/grub.cfg') do
    its('mode') { should eq 0600 }
  end
end

control '1.5.3 Set Boot Loader Password' do
  title 'Set Boot Loader Password (Scored)'
  desc  'Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters'
  impact 1.0
  describe file('/boot/grub2/grub.cfg') do
    its('content') { should match %r{/^set superusers=".*"\s*(?:#.*)?$/} }
  end
  describe file('/boot/grub2/grub.cfg') do
    its('content') { should match 'password_pbkdf2' }
  end
end

title '1.6 Additional Process Hardening'

control '1.6.1 Restrict Core_Dumps' do
  title 'Restrict Core Dumps (Scored)'
  desc  'A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file. The system provides the ability to set a soft limit for core dumps, but this can be overridden by the user.'
  impact 1.0
  describe file('/etc/security/limits.conf') do
    its('content') { should match %r{/^\s*\*\shard\score\s0(\s+#.*)?$/} }
  end
  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should_not be_nil }
  end
  describe kernel_parameter('fs.suid_dumpable') do
    its('value') { should eq 0 }
  end
end

control '1.6.2 Enable Randomized Virtual Memory Region Placement' do
  title 'Enable Randomized Virtual Memory Region Placement (Scored)'
  desc  'Set the system flag to force randomized virtual memory region placement.'
  impact 1.0
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should_not be_nil }
  end
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

title '1.7 Use the Latest OS Release'

control '1.7 Use the Latest OS Release' do
  title 'Use the Latest OS Release (Not Scored)'
  desc  'Periodically, Red Hat releases updates to the Red Hat operating system to support new hardware platforms, deliver new functionality as well as the bundle together a set of patches that can be tested as a unit.'
  impact 0.0
end

title '2 OS Services'
title '2.1 Remove Legacy Services'

control '2.1.1 Remove telnet-server' do
  title 'Remove telnet-server (Scored)'
  desc  'The telnet-server package contains the telnetd daemon, which accepts connections from users from other systems via the telnet protocol.'
  impact 1.0
  describe package('telnet-server') do
    it { should_not be_installed }
  end
end

control '2.1.2 Remove telnet Clients' do
  title 'Remove telnet Clients (Scored)'
  desc  'The telnet package contains the telnet client, which allows users to start connections to other systems via the telnet protocol.'
  impact 1.0
  describe package('telnet') do
    it { should_not be_installed }
  end
end

control '2.1.3 Remove rsh-server' do
  title 'Remove rsh-server (Scored)'
  desc  'The Berkeley rsh-server (rsh, rlogin, rcp) package contains legacy services that exchange credentials in clear-text.'
  impact 1.0
  describe package('rsh-server') do
    it { should_not be_installed }
  end
end

control '2.1.4 Remove rsh' do
  title 'Remove rsh (Scored)'
  desc  'The rsh package contains the client commands for the rsh services.'
  impact 1.0
  describe package('rsh') do
    it { should_not be_installed }
  end
end

control '2.1.5 Remove NIS Client' do
  title 'Remove NIS Client (Scored)'
  desc  'The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client (ypbind) was used to bind a machine to an NIS server and receive the distributed configuration files.'
  impact 1.0
  describe package('ypbind') do
    it { should_not be_installed }
  end
end

control '2.1.6 Remove NIS Server' do
  title 'Remove NIS Server (Scored)'
  desc  'The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server directory service protocol for distributing system configuration files. The NIS server is a collection of programs that allow for the distribution of configuration files.'
  impact 1.0
  describe package('ypserv') do
    it { should_not be_installed }
  end
end

control '2.1.7 Remove tftp' do
  title 'Remove tftp (Scored)'
  desc  'Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot files between machines. TFTP does not support authentication and can be easily hacked. The package tftp is a client program that allows for connections to a tftp server.'
  impact 1.0
  describe package('tftp') do
    it { should_not be_installed }
  end
end

control '2.1.8 Remove tftp-server' do
  title 'Remove tftp-server (Scored)'
  desc  'Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot machines from a boot server. The package tftp-server is the server package used to define and support a TFTP server.'
  impact 1.0
  describe package('tftp-server') do
    it { should_not be_installed }
  end
end

control '2.1.9 Remove talk' do
  title 'Remove talk (Scored)'
  desc  'The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initialization of talk sessions) is installed by default.'
  impact 1.0
  describe package('talk') do
    it { should_not be_installed }
  end
end

control '2.1.10 Remove talk-server' do
  title 'Remove talk-server (Scored)'
  desc  'The talk software makes it possible for users to send and receive messages across systems through a terminal session. The talk client (allows initiate of talk sessions) is installed by default.'
  impact 1.0
  describe package('talk-server') do
    it { should_not be_installed }
  end
end

control '2.1.11 Remove xinetd' do
  title 'Remove xinetd (Scored)'
  desc  'The eXtended InterNET Daemon (xinetd) is an open source super daemon that replaced the original inetd daemon. The xinetd daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.'
  impact 1.0
  describe package('xinetd') do
    it { should_not be_installed }
  end
end if level_two_enabled

unless level_two_enabled
  control '2.1.12 Disable chargen-dgram' do
    title 'Disable chargen-dgram (Scored)'
    desc  'chargen-dgram is a network service that responds with 0 to 512 ASCII characters for each datagram it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('chargen').socket_types('dgram') do
      it { should be_disabled }
    end
  end

  control '2.1.13 Disable chargen-stream' do
    title 'Disable chargen-stream (Scored)'
    desc  'chargen-stream is a network service that responds with 0 to 512 ASCII characters for each connection it receives. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('chargen').socket_types('stream') do
      it { should be_disabled }
    end
  end

  control '2.1.14 Disable daytime-dgram' do
    title 'Disable daytime-dgram (Scored)'
    desc  'daytime-dgram is a network service that responds with the servers current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('daytime').socket_types('dgram') do
      it { should be_disabled }
    end
  end

  control '2.1.15 Disable daytime-stream' do
    title 'Disable daytime-stream (Scored)'
    desc  'daytime-stream is a network service that responds with the servers current date and time. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('daytime').socket_types('stream') do
      it { should be_disabled }
    end
  end

  control '2.1.16 Disable echo-dgram' do
    title 'Disable echo-dgram (Scored)'
    desc  'echo-dgram is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('echo').socket_types('dgram') do
      it { should be_disabled }
    end
  end

  control '2.1.17 Disable echo-stream' do
    title 'Disable echo-stream (Scored)'
    desc  'echo-stream is a network service that responds to clients with the data sent to it by the client. This service is intended for debugging and testing purposes. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('echo').socket_types('stream') do
      it { should be_disabled }
    end
  end

  control '2.1.18 Disable tcpmux-server' do
    title 'Disable tcpmux-server (Scored)'
    desc  'tcpmux-server is a network service that allows a client to access other network services running on the server. It is recommended that this service be disabled.'
    impact 1.0
    describe xinetd_conf.services('tcpmux').socket_types('stream') do
      it { should be_disabled }
    end
  end
end

title '3 Special Purpose Services'

control '3.1 Set Daemon umask' do
  title 'Set Daemon umask (Scored)'
  desc  'Set the default umask for all processes started at boot time. The settings in umask selectively turn off default permission when a file is created by a daemon process.'
  impact 1.0
  describe file('/etc/sysconfig/init') do
    its('content') { should match %r{/^\s*umask\s+027\s*(?:#.*)?$/} }
  end
end

control '3.2 Remove the X Window System' do
  title 'Remove the X Window System (Scored)'
  desc  'The X Window system provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Window system is typically used on desktops where users login, but not on servers where users typically do not login.'
  impact 1.0
  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end
  describe file('/etc/systemd/system/default.target') do
    it { should exist }
  end
  describe file('/etc/systemd/system/default.target') do
    its('path') { should_not match %r{/^.*\/graphical\.target$/} }
  end
end

control '3.3 Disable Avahi Server' do
  title 'Disable Avahi Server (Scored)'
  desc  'Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.'
  impact 1.0
  describe service('avahi-daemon').params do
    its('UnitFileState') { should_not eq 'enabled' }
  end
end

control '3.4 Disable Print Server - CUPS' do
  title 'Disable Print Server - CUPS (Not Scored)'
  desc  'The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.'
  impact 0.0
  describe service('cups').params do
    its('UnitFileState') { should_not eq 'enabled' }
  end
  tag remediation: 'http://www.cups.org'
end

control '3.5 Remove DHCP Server' do
  title 'Remove DHCP Server (Scored)'
  desc  'The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses.'
  impact 1.0
  describe package('dhcp') do
    it { should_not be_installed }
  end
  tag remediation: 'http://www.isc.org/software/dhcp'
end

control '3.6 Configure Network Time Protocol NTP' do
  title 'Configure Network Time Protocol (NTP) (Scored)'
  desc  'The Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. The version of NTP delivered with Red Hat can be found at http://www.ntp.org. NTP can be configured to be a client and/or a server.'
  impact 1.0
  describe package('ntp') do
    it { should be_installed }
  end
  # has the restrict parameters in the ntp config
  describe file('/etc/ntp.conf') do
    its('content') { should match %r{/^\s*restrict\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/} }
  end
  describe file('/etc/ntp.conf') do
    its('content') { should match %r{/^\s*restrict\s+-6\s+default(?=[^#]*\s+kod)(?=[^#]*\s+nomodify)(?=[^#]*\s+notrap)(?=[^#]*\s+nopeer)(?=[^#]*\s+noquery)(\s+kod|\s+nomodify|\s+notrap|\s+nopeer|\s+noquery)*\s*(?:#.*)?$/} }
  end
  # has at least one NTP server defined
  describe file('/etc/ntp.conf') do
    its('content') { should match %r{/^\s*server\s+\S+/} }
  end
  # is configured to start ntpd as a nonprivileged user
  describe file('/etc/sysconfig/ntpd') do
    its('content') { should match %r{/^\s*OPTIONS='[^']*-u ntp:ntp[^']*'\s*(?:#.*)?$/} }
  end
  tag remediation: 'http://www.ntp.org'
end

control '3.7 Remove LDAP' do
  title 'Remove LDAP (Not Scored)'
  desc  'The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database. The default client/server LDAP application for Red Hat is OpenLDAP.'
  impact 0.0
  describe package('openldap-servers') do
    it { should_not be_installed }
  end
  describe package('openldap-clients') do
    it { should_not be_installed }
  end
  tag remediation: 'http://www.openldap.org.'
end

control '3.8 Disable NFS and RPC' do
  title 'Disable NFS and RPC (Not Scored)'
  desc  'The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.'
  impact 0.0
  describe service('nfslock') do
    it { should_not be_enabled }
  end
  describe service('rpcgssd') do
    it { should_not be_enabled }
  end
  describe service('rpcbind') do
    it { should_not be_enabled }
  end
  describe service('rpcidmapd') do
    it { should_not be_enabled }
  end
  describe service('rpcsvcgssd') do
    it { should_not be_enabled }
  end
end

control '3.9 Remove DNS Server' do
  title 'Remove DNS Server (Not Scored)'
  desc  'The Domain Name System (DNS) is a hierarchical naming system that maps names to IP addresses for computers, services and other resources connected to a network.'
  impact 0.0
  describe package('bind') do
    it { should_not be_installed }
  end
end

control '3.10 Remove FTP Server' do
  title 'Remove FTP Server (Not Scored)'
  desc  'The File Transfer Protocol (FTP) provides networked computers with the ability to transfer files.'
  impact 0.0
  describe package('vsftpd') do
    it { should_not be_installed }
  end
end

control '3.11 Remove HTTP Server' do
  title 'Remove HTTP Server (Not Scored)'
  desc  'HTTP or web servers provide the ability to host web site content. The default HTTP server shipped with Red Hat Linux is Apache.'
  impact 0.0
  describe package('httpd') do
    it { should_not be_installed }
  end
end

control '3.12 Remove Dovecot IMAP and POP3 services' do
  title 'Remove Dovecot (IMAP and POP3 services) (Not Scored)'
  desc  'Dovecot is an open source IMAP and POP3 server for Linux based systems.'
  impact 0.0
  describe package('dovecot') do
    it { should_not be_installed }
  end
  tag remediation: 'http://www.dovecot.org'
end

control '3.13 Remove Samba' do
  title 'Remove Samba (Not Scored)'
  desc  'The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Small Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.'
  impact 0.0
  describe package('samba') do
    it { should_not be_installed }
  end
end

control '3.14 Remove HTTP Proxy Server' do
  title 'Remove HTTP Proxy Server (Not Scored)'
  desc  'The default HTTP proxy package shipped with Red Hat Linux is squid.'
  impact 0.0
  describe package('squid') do
    it { should_not be_installed }
  end
end

control '3.15 Remove SNMP Server' do
  title 'Remove SNMP Server (Not Scored)'
  desc  'The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.'
  impact 0.0
  describe package('net-snmp') do
    it { should_not be_installed }
  end
end

control '3.16 Configure Mail Transfer Agent for Local-Only Mode' do
  title 'Configure Mail Transfer Agent for Local-Only Mode (Scored)'
  desc  'Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to listen for incoming mail and transfer the messages to the appropriate user or mail server. If the system is not intended to be a mail server, it is recommended that the MTA be configured to only process local mail. By default, the MTA is set to loopback mode on RHEL7.'
  impact 1.0
  port(25).addresses.each do |entry|
    describe entry do
      it { should_not match %r{/^(?!127\.0\.0\.1|::1).*$/} }
    end
  end
end

title '4 Network Configuration and Firewalls'
title '4.1 Modify Network Parameters (Host Only)'

control '4.1.1 Disable IP Forwarding' do
  title 'Disable IP Forwarding (Scored)'
  desc  'The net.ipv4.ip_forward flag is used to tell the server whether it can forward packets or not. If the server is not to be used as a router, set the flag to 0.'
  impact 1.0
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should_not be_nil }
  end
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
end

control '4.1.2 Disable Send Packet Redirects' do
  title 'Disable Send Packet Redirects (Scored)'
  desc  'ICMP Redirects are used to send routing information to other hosts. As a host itself does not act as a router (in a host only configuration), there is no need to send redirects.'
  impact 1.0
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.send_redirects') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
end

title '4.2 Modify Network Paramters (Host and Router)'

control '4.2.1 Disable Source Routed Packet Acceptance' do
  title 'Disable Source Routed Packet Acceptance (Scored)'
  desc  'In networking, source routing allows a sender to partially or fully specify the route packets take through a network. In contrast, non-source routed packets travel a path determined by routers in the network. In some cases, systems may not be routable or reachable from some locations (e.g. private addresses vs. Internet routable), and so source routed packets would need to be used.'
  impact 1.0
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
end

control '4.2.2 Disable ICMP Redirect Acceptance' do
  title 'Disable ICMP Redirect Acceptance (Scored)'
  desc  'ICMP redirect messages are packets that convey routing information and tell your host (acting as a router) to send packets via an alternate path. It is a way of allowing an outside routing device to update your system routing tables. By setting net.ipv4.conf.all.accept_redirects to 0, the system will not accept any ICMP redirect messages, and therefore, wont allow outsiders to update the systems routing tables.'
  impact 1.0
  describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.default.accept_redirects') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
end

control '4.2.4 Log Suspicious Packets' do
  title 'Log Suspicious Packets (Scored)'
  desc  'When enabled, this feature logs packets with un-routable source addresses to the kernel log.'
  impact 1.0
  describe kernel_parameter('net.ipv4.conf.all.log_martians') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv4.conf.default.log_martians') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
end

control '4.2.5 Enable Ignore Broadcast Requests' do
  title 'Enable Ignore Broadcast Requests (Scored)'
  desc  'Setting net.ipv4.icmp_echo_ignore_broadcasts to 1 will cause the system to ignore all ICMP echo and timestamp requests to broadcast and multicast addresses.'
  impact 1.0
  describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
end

control '4.2.6 Enable Bad Error Message Protection' do
  title 'Enable Bad Error Message Protection (Scored)'
  desc  'Setting icmp_ignore_bogus_error_responses to 1 prevents the kernel from logging bogus responses (RFC-1122 non-compliant) from broadcast reframes, keeping file systems from filling up with useless log messages.'
  impact 1.0
  describe kernel_parameter('net.ipv4.icmp_ignore_bogus_error_responses') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
end

control '4.2.8 Enable TCP SYN Cookies' do
  title 'Enable TCP SYN Cookies (Scored)'
  desc  'When tcp_syncookies is set, the kernel will handle TCP SYN packets normally until the half-open connection queue is full, at which time, the SYN cookie functionality kicks in. SYN cookies work by not using the SYN queue at all. Instead, the kernel simply replies to the SYN with a SYN|ACK, but will include a specially crafted TCP sequence number that encodes the source and destination IP address and port number and the time the packet was sent. A legitimate connection would send the ACK packet of the three way handshake with the specially crafted sequence number. This allows the server to verify that it has received a valid response to a SYN cookie and allow the connection, even though there is no corresponding SYN in the queue.'
  impact 1.0
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
end

title '4.3 Wireless Networking'

control '4.3.1 Deactivate Wireless Interfaces' do
  title 'Deactivate Wireless Interfaces (Not Scored)'
  desc  'Wireless networking is used when wired networks are unavailable. Red Hat contains a wireless tool kit to allow system administrators to configure and use wireless networks.'
  impact 0.0
end if level_two_enabled

title '4.4 IPv6'
title '4.4.1 Configure IPv6'

control '4.4.1.1 Disable IPv6 Router Advertisements' do
  title 'Disable IPv6 Router Advertisements (Not Scored)'
  desc 'This setting disables the systems ability to accept router advertisements'
  impact 0.0
  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
end unless ipv6_disabled

control '4.4.1.2 Disable IPv6 Redirect Acceptance' do
  title 'Disable IPv6 Redirect Acceptance (Not Scored)'
  desc 'This setting precents the system from accepting ICMP redirects. ICMP redirects tell the system about alternate routes for sending traffic'
  impact 0.0
  describe kernel_parameter('net.ipv6.conf.all.accept_redirects') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_redirects') do
    its('value') { should_not be_nil }
    its('value') { should eq 0 }
  end
end unless ipv6_disabled

control '4.4.2 Disable IPv6' do
  title 'Disable IPv6 (Not Scored)'
  desc 'Although IPv6 has many advantages over IPv4, few organization have implemented IPv6'
  impact 0.0
  describe kernel_parameter('net.ipv6.conf.all.disable_ipv6') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
  describe kernel_parameter('net.ipv6.conf.default.disable_ipv6') do
    its('value') { should_not be_nil }
    its('value') { should eq 1 }
  end
end if ipv6_disabled

title '4.5 Install TCP Wrappers'

control '4.5.1 Install TCP_Wrappers' do
  title 'Install TCP Wrappers (Not Scored)'
  desc  'TCP Wrappers provides a simple access list and standardized logging method for services capable of supporting it. In the past, services that were called from inetd and xinetd supported the use of tcp wrappers. As inetd and xinetd have been falling in disuse, any service that can support tcp wrappers will have the libwrap.so library attached to it.'
  impact 0.0
end

control '4.5.2 Create /etc/hosts.allow' do
  title 'Create /etc/hosts.allow (Not Scored)'
  desc  'The /etc/hosts.allow file specifies which IP addresses are permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.deny file.'
  impact 0.0
  describe file('/etc/hosts.allow') do
    it { should exist }
  end
end

control '4.5.3 Verify Permissions on /etc/hosts.allow' do
  title 'Verify Permissions on /etc/hosts.allow (Scored)'
  desc  'The /etc/hosts.allow file contains networking information that is used by many applications and therefore must be readable for these applications to operate.'
  impact 1.0
  describe file('/etc/hosts.allow') do
    its('mode') { should eq 0644 }
  end
end

control '4.5.4 Create /etc/hosts.deny' do
  title 'Create /etc/hosts.deny (Not Scored)'
  desc  'The /etc/hosts.deny file specifies which IP addresses are not permitted to connect to the host. It is intended to be used in conjunction with the /etc/hosts.allow file.'
  impact 0.0
  describe file('/etc/hosts.deny') do
    it { should exist }
  end
end

control '4.5.5 Verify Permissions on /etc/hosts.deny' do
  title 'Verify Permissions on /etc/hosts.deny (Scored)'
  desc  'The /etc/hosts.deny file contains network information that is used by many system applications and therefore must be readable for these applications to operate.'
  impact 1.0
  describe file('/etc/hosts.deny') do
    its('mode') { should eq 0644 }
  end
end

title '4.6 Uncommon Network Protocols'

control '4.6.1 Disable DCCP' do
  title 'Disable DCCP (Not Scored)'
  desc  'The Datagram Congestion Control Protocol (DCCP) is a transport layer protocol that supports streaming media and telephony. DCCP provides a way to gain access to congestion control, without having to do it at the application layer, but does not provide in-sequence delivery.'
  impact 0.0
  describe kernel_module('dccp') do
    it { should_not be_loaded }
  end
end

control '4.6.2 Disable_SCTP' do
  title 'Disable SCTP (Not Scored)'
  desc  'The Stream Control Transmission Protocol (SCTP) is a transport layer protocol used to support message oriented communication, with several streams of messages in one connection. It serves a similar function as TCP and UDP, incorporating features of both. It is message-oriented like UDP, and ensures reliable in-sequence transport of messages with congestion control like TCP.'
  impact 0.0
  describe kernel_module('sctp') do
    it { should_not be_loaded }
  end
end

control '4.6.3 Disable RDS' do
  title 'Disable RDS (Not Scored)'
  desc  'The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide low-latency, high-bandwidth communications between cluster nodes. It was developed by the Oracle Corporation.'
  impact 0.0
  describe kernel_module('rds') do
    it { should_not be_loaded }
  end
end

control '4.6.4 Disable TIPC' do
  title 'Disable TIPC (Not Scored)'
  desc  'The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communication between cluster nodes.'
  impact 0.0
  describe kernel_module('tipc') do
    it { should_not be_loaded }
  end
end

control '4.7 Enable firewalld' do
  title 'Enable firewalld (Scored)'
  desc  'IPtables is an application that allows a system administrator to configure the IP tables, chains and rules provided by the Linux kernel firewall.  The firewalld service provides a dynamic firewall allowing changes to be made at anytime without disruptions cause by reloading.'
  impact 1.0
  describe service('firewalld').params do
    its('UnitFileState') { should eq 'enabled' }
  end
end

title '5 Logging anad Auditing'
title '5.1 Configure rsyslog'

control '5.1.1 Install the rsyslog package' do
  title 'Install the rsyslog package (Scored)'
  desc  'The rsyslog package is a third party package that provides many enhancements to syslog, such as multi-threading, TCP communication, message filtering and data base support. As of RHEL 5.2, rsyslog is available as part of the core distribution.'
  impact 1.0
  describe package('rsyslog') do
    it { should be_installed }
  end
end

control '5.1.2 Activate the rsyslog Service' do
  title 'Activate the rsyslog Service (Scored)'
  desc  'The systemctl command can be used to ensure that the rsyslog service is turned on.'
  impact 1.0
  describe service('rsyslog').params do
    its('UnitFileState') { should eq 'enabled' }
  end
end

control '5.1.3 Configure /etc/rsyslog.conf' do
  title 'Configure /etc/rsyslog.conf (Not Scored)'
  desc  'The /etc/rsyslog.conf file specifies rules for logging and which files are to be used to log certain classes of messages.'
  impact 0.0
end

control '5.1.4 Create and Set Permissions on rsyslog Log Files' do
  title 'Create and Set Permissions on rsyslog Log Files (Scored)'
  desc  'A log file must already exist for rsyslog to be able to write to it.'
  impact 1.0
  file('/etc/rsyslog.conf').content.to_s.scan(%r{/^[^##{$ORS}r\n](.*\s+\/.*)$/}).flatten.map { |x| x.scan(%r{/^[^##{$ORS}r\n].*\s+(\/.*)$/}) }.flatten.each do |entry|
    describe file(entry) do
      it { should exist }
    end
    describe file(entry) do
      its('mode') { should eq 0640 }
    end
  end
end

control '5.1.5 Configure rsyslog to Send Logs to a Remote Log Host' do
  title 'Configure rsyslog to Send Logs to a Remote Log Host (Scored)'
  desc  'The rsyslog utility supports the ability to send logs it gathers to a remote log host running syslogd(8) or to receive messages from remote hosts, reducing administrative overhead.'
  impact 1.0
  describe file('/etc/rsyslog.conf') do
    its('content') { should match %r{/^\*\.\*\s+@/} }
  end
end

control '5.1.6 Accept Remote rsyslog Messages Only on Designated Log Hosts' do
  title 'Accept Remote rsyslog Messages Only on Designated Log Hosts (Not Scored)'
  desc  'By default, rsyslog does not listen for log messages coming in from remote systems. The ModLoad tells rsyslog to load the imtcp.so module so it can listen over a network via TCP. The InputTCPServerRun option instructs rsyslogd to listen on the specified TCP port.'
  impact 0.0
end

title '5.2 Configure System Accounting (audited)'
title '5.2.1 Configure Data Retention'

if level_two_enabled
  control '5.2.1.1 Configure Audit Log Storage Size' do
    title 'Configure Audit Log Storage Size (Not Scored)'
    desc  'Configure the maximum size of the audit log file (default 6mb). Once the log reaches the maximum size, it will be rotated and a new log file will be started.'
    impact 0.0
  end

  control '5.2.1.2 Disable System on Audit Log Full' do
    title 'Disable System on Audit Log Full (Not Scored)'
    desc  'The auditd daemon can be configured to halt the system when the audit logs are full.'
    impact 0.0
  end

  control '5.2.1.3 Keep All Auditing Information' do
    title 'Keep All Auditing Information (Scored)'
    desc  'Normally, auditd will hold 4 logs of maximum log file size before deleting older log files.'
    impact 1.0
    describe file('/etc/audit/auditd.conf') do
      its('content') { should match 'max_log_file_action = keep_logs' }
    end
  end

  control '5.2.2 Enable auditd Service' do
    title 'Enable auditd Service Scored)'
    desc  'Turn on the auditd daemon to record system events.'
    impact 1.0
    describe service('auditd').params do
      its('UnitFileState') { should eq 'enabled' }
    end
  end

  control '5.2.3 Enable Auditing for Processes That Start Prior to auditd' do
    title 'Enable Auditing for Processes That Start Prior to auditd (Scored)'
    desc  'Configure grub so that processes that are capable of being audited can be audited even if they start up prior to auditd startup.'
    impact 1.0
    describe file('/boot/grub2/grub.cfg') do
      its('content') { should match %r{/^\s*linux(16)?\s+(?=[^#]*audit=1).*$/} }
    end
  end

  control '5.2.4 Record Events That Modify Date and Time Information' do
    title 'Record Events That Modify Date and Time Information (Scored)'
    desc  'Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the adjtimex (tune kernel clock), settimeofday (Set time, using timeval and timezone structures) stime (using seconds since 1/1/1970) or clock_settime (allows for the setting of several internal clocks and timers) system calls have been executed and always write an audit record to the /var/log/audit.log file upon exit, tagging the records with the identifier time-change'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/localtime -p wa -k time-change$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S clock_settime -k time-change$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change/} }
    end
    describe.one do
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S clock_settime -k time-change$/} }
      end
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change$/} }
      end
      describe command('uname -m').stdout do
        its('strip') { should_not eq 'x86_64' }
      end
    end
  end

  control '5.2.5 Record Events That Modify User/Group Information' do
    title 'Record Events That Modify User/Group Information (Scored)'
    desc  'Record events affecting the group, passwd (user IDs), shadow and gshadow (passwords) or /etc/security/opasswd (old passwords, based on remember parameter in the PAM configuration) files. The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier identity in the audit log file.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/group -p wa -k identity$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/passwd -p wa -k identity$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/gshadow -p wa -k identity$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/shadow -p wa -k identity$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/security\/opasswd -p wa -k identity$/} }
    end
  end

  control '5.2.6 Record Events That Modify the Systems Network Environment' do
    title 'Record Events That Modify the Systems Network Environment (Scored)'
    desc  'Record changes to network environment files or system calls. The below parameters monitor the sethostname (set the systems host name) or setdomainname (set the systems domainname) system calls, and write an audit event on system call exit. The other parameters monitor the /etc/issue and /etc/issue.net files (messages displayed pre-login), /etc/hosts (file containing host names and associated IP addresses) and /etc/sysconfig/network (directory containing network interface scripts and configurations) files.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/issue -p wa -k system-locale$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/issue.net -p wa -k system-locale$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/hosts -p wa -k system-locale$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/sysconfig\/network -p wa -k system-locale$/} }
    end
    describe.one do
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale$/} }
      end
      describe command('uname -m').stdout do
        its('strip') { should_not eq 'x86_64' }
      end
    end
  end

  control '5.2.7 Record Events That Modify the Systems Mandatory Access Controls' do
    title 'Record Events That Modify the Systems Mandatory Access Controls (Scored)'
    desc  'Monitor SELinux mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the /etc/selinux directory.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/selinux\/ -p wa -k MAC-policy$/} }
    end
  end

  control '5.2.8Collect Login and Logout Events' do
    title 'Collect Login and Logout Events (Scored)'
    desc  'Monitor login and logout events. The parameters below track changes to files associated with login/logout events. The file /var/log/faillog tracks failed events from login. The file /var/log/lastlog maintain records of the last time a user successfully logged in. The file /var/log/btmp keeps track of failed login attempts and can be read by entering the command /usr/bin/last -f /var/log/btmp. All audit records will be tagged with the identifier logins.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/var\/log\/faillog -p wa -k logins$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/var\/log\/lastlog -p wa -k logins$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/var\/log\/tallylog -p wa -k logins$/} }
    end
  end

  control '5.2.9 Collect Session Initiation Information' do
    title 'Collect Session Initiation Information (Scored)'
    desc  'Monitor session initiation events. The parameters in this section track changes to the files associated with session events. The file /var/run/utmp file tracks all currently logged in users. The /var/log/wtmp file tracks logins, logouts, shutdown and reboot events. All audit records will be tagged with the identifier session.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/var\/run\/utmp -p wa -k session$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/var\/log\/wtmp -p wa -k session$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/var\/log\/btmp -p wa -k session$/} }
    end
  end

  control '5.2.10 Collect Discretionary Access Control Permission Modification Events' do
    title 'Collect Discretionary Access Control Permission Modification Events (Scored)'
    desc  'Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The chmod, fchmod and fchmodat system calls affect the permissions associated with a file. The chown, fchown, fchownat and lchown system calls affect owner and group attributes on a file. The setxattr, lsetxattr, fsetxattr (set extended file attributes) and removexattr, lremovexattr, fremovexattr (remove extended file attributes) control extended file attributes. In all cases, an audit record will only be written for non-system userids (auid >= 1000) and will ignore Daemon events (auid = 4294967295). All audit records will be tagged with the identifier perm_mod.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod$/} }
    end
    describe.one do
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod$/} }
      end
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod$/} }
      end
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod$/} }
      end
      describe command('uname -m').stdout do
        its('strip') { should_not eq 'x86_64' }
      end
    end
  end

  control '5.2.11 Collect Unsuccessful Unauthorized Access Attempts to Files' do
    title 'Collect Unsuccessful Unauthorized Access Attempts to Files (Scored)'
    desc  'Monitor for unsuccessful attempts to access files. The parameters below are associated with system calls that control creation (creat), opening (open, openat) and truncation (truncate, ftruncate) of files. An audit log record will only be written if the user is a non-privileged user (auid > = 1000), is not a Daemon event (auid=4294967295) and if the system call returned EACCES (permission denied to the file) or EPERM (some other permanent error associated with the specific system call). All audit records will be tagged with the identifier access.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access$/} }
    end
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access$/} }
    end
    describe.one do
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access$/} }
      end
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access$/} }
      end
      describe command('uname -m').stdout do
        its('strip') { should_not eq 'x86_64' }
      end
    end
  end

  control '5.2.12 Collect Use of Privileged Commands' do
    title 'Collect Use of Privileged Commands (Scored)'
    desc  'Monitor privileged programs (those that have the setuid and/or setgid bit set on execution) to determine if unprivileged users are running these commands.'
    impact 1.0
    command('find / -regex .\\*/.\\+ -type f -perm /06000').stdout.split.map { |x| '^\\-a (always,exit|exit,always) \\-F path=' + x }.map { |x| x + ' \\-F perm=x \\-F auid>=1000 \\-F auid!=4294967295 \\-k privileged$' }.each do |entry|
      describe file('/etc/audit/audit.rules') do
        its('content') { should match Regexp.new(entry) }
      end
    end
  end

  control '5.2.13 Collect Successful File System Mounts' do
    title 'Collect Successful File System Mounts (Scored)'
    desc  'Monitor the use of the mount system call. The mount (and umount) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts$/} }
    end
    describe.one do
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts$/} }
      end
      describe command('uname -m').stdout do
        its('strip') { should_not eq 'x86_64' }
      end
    end
  end

  control '5.2.14 Collect File Deletion Events by User' do
    title 'Collect File Deletion Events by User (Scored)'
    desc  'Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for the unlink (remove a file), unlinkat (remove a file attribute), rename (rename a file) and renameat (rename a file attribute) system calls and tags them with the identifier delete'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete$/} }
    end
    describe.one do
      describe file('/etc/audit/audit.rules') do
        its('content') { should match %r{/^-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete$/} }
      end
      describe command('uname -m').stdout do
        its('strip') { should_not eq 'x86_64' }
      end
    end
  end

  control '5.2.15 Collect Changes to System Administration Scope (sudoers)' do
    title 'Collect Changes to System Administration Scope (sudoers) (Scored)'
    desc  'Monitor scope changes for system administrations. If the system has been properly configured to force system administrators to log in as themselves first and then use the sudo command to execute privileged commands, it is possible to monitor changes in scope. The file /etc/sudoers will be written to when the file or its attributes have changed. The audit records will be tagged with the identifier scope.'
    impact 1.0
    describe file('/etc/audit/audit.rules') do
      its('content') { should match %r{/^-w \/etc\/sudoers -p wa -k scope$/} }
    end
  end
  #
  # control "xccdf_org.cisecurity.benchmarks_rule_5.2.16_Collect_System_Administrator_Actions_sudolog" do
  #   title "Collect System Administrator Actions (sudolog)"
  #   desc  "Monitor the sudo log file. If the system has been properly configured to disable the use of the su command and force all administrators to have to log in first and then use sudo to execute privileged commands, then all administrator commands will be logged to /var/log/sudo.log. Any time a command is executed, an audit event will be triggered as the /var/log/sudo.log file will be opened for write and the executed administration command will be written to the log."
  #   impact 1.0
  #   describe file("/etc/audit/audit.rules") do
  #     its("content") { should match /^-w \/var\/log\/sudo.log -p wa -k actions$/ }
  #   end
  # end
  #
  # control "xccdf_org.cisecurity.benchmarks_rule_5.2.17_Collect_Kernel_Module_Loading_and_Unloading" do
  #   title "Collect Kernel Module Loading and Unloading"
  #   desc  "Monitor the loading and unloading of kernel modules. The programs insmod (install a kernel module), rmmod (remove a kernel module), and modprobe (a more sophisticated program to load and unload modules, as well as some other features) control loading and unloading of modules. The init_module (load a module) and delete_module (delete a module) system calls control loading and unloading of modules. Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of \"modules\"."
  #   impact 1.0
  #   describe file("/etc/audit/audit.rules") do
  #     its("content") { should match /^-w \/sbin\/insmod -p x -k modules$/ }
  #   end
  #   describe file("/etc/audit/audit.rules") do
  #     its("content") { should match /^-w \/sbin\/rmmod -p x -k modules$/ }
  #   end
  #   describe file("/etc/audit/audit.rules") do
  #     its("content") { should match /^-w \/sbin\/modprobe -p x -k modules$/ }
  #   end
  #   describe.one do
  #     describe command("uname -m").stdout do
  #       its("strip") { should eq "x86_64" }
  #     end
  #     describe file("/etc/audit/audit.rules") do
  #       its("content") { should match /^-a always,exit -F arch=b32 -S init_module -S delete_module -k modules$/ }
  #     end
  #   end
  #   describe.one do
  #     describe command("uname -m").stdout do
  #       its("strip") { should_not eq "x86_64" }
  #     end
  #     describe file("/etc/audit/audit.rules") do
  #       its("content") { should match /^-a always,exit -F arch=b64 -S init_module -S delete_module -k modules$/ }
  #     end
  #   end
  # end
end
