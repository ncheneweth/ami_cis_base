# Build Ubuntu 14.04 AMI with Packer and ansible_playbook

## Test Ansible role
The ansible role is defined within roles/cis and this where the test-kitchen
definition resides. There is a Rakefile in roles/cis to automate the build/verify process

To test the role:

rake validate

The rakefile is setup to update the Vagrant box used here as well (which is
  why there a Vagrant file here as well)

## Packer build

to build the ami:

packer build packer.json

The file manifest.json will contain the ami id created
