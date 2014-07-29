#!/usr/bin/env bash

sudo apt-get update
sudo apt-get install python-software-properties --yes --force-yes
# Add PPA for ZeroVM packages
sudo add-apt-repository ppa:zerovm-ci/zerovm-latest -y
sudo apt-get update
sudo apt-get install git zerovm-cli zpm --yes --force-yes


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
git clone https://github.com/zerovm/zerocloud.git $HOME/zerocloud
cd $HOME/zerocloud
sudo python setup.py install

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
