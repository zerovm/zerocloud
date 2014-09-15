#!/usr/bin/env bash

sudo apt-get update
sudo apt-get install python-software-properties --yes --force-yes
# Add PPA for ZeroVM packages
sudo add-apt-repository ppa:zerovm-ci/zerovm-latest -y
sudo apt-get update
sudo apt-get install git python-pip zerovm --yes --force-yes
sudo pip install python-swiftclient==2.2.0


###
# DevStack
git clone https://github.com/openstack-dev/devstack.git $HOME/devstack
cd $HOME/devstack
touch local.conf
read -d '' LOCAL_CONF << EOF
[[local|localrc]]
ADMIN_PASSWORD=admin
HOST_IP=127.0.0.1
disable_all_services
enable_service key mysql s-proxy s-object s-container s-account
EOF
echo "$LOCAL_CONF" >> local.conf
./stack.sh

###
# ZeroCloud
# Install is from the code on the host, mapped to /zerocloud
cd /zerocloud-root
sudo python setup.py develop

###
# Python system image for ZeroCloud/ZeroVM
sudo mkdir /usr/share/zerovm
cd /usr/share/zerovm
sudo wget -q http://packages.zerovm.org/zerovm-samples/python.tar

###
# Add ZeroCloud middleware to swift config
# This includes setting up the cross-compiled python
# distribution for ZeroVM.
python /vagrant/configure_swift.py

###
# Set `demo` user password
source /vagrant/adminrc
keystone user-password-update --pass demo demo
