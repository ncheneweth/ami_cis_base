#!/bin/bash
# setup ssh max sessions while we're at it so ansible works smoothly
echo "MaxSessions 30" >> /etc/ssh/sshd_config
service sshd restart

echo "none /dev/shm tmpfs rw,nodev,nosuid,noexec 0 0" >> /etc/fstab
echo "/dev/vgpool/temp /tmp  xfs  rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
echo "/tmp /var/tmp none rw,noexec,nosuid,nodev,bind 0 0" >> /etc/fstab
echo "/dev/vgpool/var_root /var  xfs    defaults,discard  	0 0" >> /etc/fstab
echo "/dev/vgpool/var_log /var/log  xfs    defaults,discard   	0 0" >> /etc/fstab
echo "/dev/vgpool/var_audit /var/log/audit  xfs    defaults,discard  	0 0" >> /etc/fstab
echo "/dev/vgpool/home_root /home  xfs    defaults,nodev,discard  	0 0" >> /etc/fstab
