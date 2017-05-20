#!/bin/bash
# build out paritiions for new mount points using
# space left over on the root device_name

sudo parted /dev/xvda  mkpart primary xfs 8Gib 100%
sudo fdisk -l /dev/xvda
#
sudo parted set 2 lvm on
sudo pvcreate /dev/xvda2
sudo vgcreate vgpool /dev/xvda2
echo "create logical volumes now"
sudo lvcreate -L 2G -n temp vgpool
sudo lvcreate -L 2G -n var_root vgpool
sudo lvcreate -L 5G -n var_log vgpool
sudo lvcreate -L 2G -n home_root vgpool
sudo lvcreate -L 5G -n var_audit vgpool
sudo lvcreate -l 100%FREE -n var_lib_docker vgpool
echo "Logical Volumes created"
echo "Creating filesystems"
sudo mkfs -t xfs /dev/vgpool/temp
sudo mkfs -t xfs /dev/vgpool/var_root
sudo mkfs -t xfs  /dev/vgpool/var_log
sudo mkfs -t xfs /dev/vgpool/var_audit
sudo mkfs -t xfs /dev/vgpool/home_root
echo "file systems created"

# setup mounts in fstab
sudo /home/ubuntu/setup-mounts.sh

echo "moving var"
sudo mkdir /mnt/var
sudo mount -t xfs /dev/vgpool/var_root /mnt/var
cd /var
sudo cp -ax * /mnt/var
cd /
sudo umount /dev/vgpool/var_root
sudo mv var var.old
sudo mkdir /var
sudo mount /var
echo "moved /var"

echo "moving var/log"
sudo mkdir /mnt/var_log
sudo mount -t xfs /dev/vgpool/var_log /mnt/var_log
cd /var/log
sudo cp -ax * /mnt/var_log
cd /var
sudo mv log log.old
sudo mkdir /var/log
sudo umount /dev/vgpool/var_log
sudo mount /var/log
echo "moved /var/log"

echo "moving home"
sudo mkdir /mnt/home_root
sudo mount -t xfs /dev/vgpool/home_root /mnt/home_root
cd /home
sudo cp -ax * /mnt/home_root
cd /
sudo mv home home.old
sudo mkdir /home
sudo umount /dev/vgpool/home_root
sudo mount /home

echo "moved /home"

echo "create /var/log/audit"
sudo mkdir /var/log/audit
sudo mount /var/log/audit
echo "mounted /var/log/audit"

echo "install python"
sudo apt-get install -y python

echo "cleanup scripts"
sudo rm /home/ubuntu/setup-mounts.sh
