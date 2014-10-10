#!/usr/bin/env bash
DEVSTACK_VERSION=f95fe33dcb7e4b261e1ff7aab877563709065158
# swauth super admin key
SWAUTH_SA_KEY=swauthkey

sudo apt-get update
sudo apt-get install python-software-properties --yes --force-yes
# Add PPA for ZeroVM packages
sudo add-apt-repository ppa:zerovm-ci/zerovm-latest -y
# Add repo for new node packages
sudo add-apt-repository 'deb https://deb.nodesource.com/node precise main'
wget -O- https://deb.nodesource.com/gpgkey/nodesource.gpg.key \
    | sudo apt-key add -

sudo apt-get update
sudo apt-get install git python-pip zerovm --yes --force-yes
sudo pip install python-swiftclient==2.2.0
sudo pip install python-keystoneclient


###
# Swauth: Auth middleware for Swift
git clone https://github.com/gholt/swauth.git $HOME/swauth
cd $HOME/swauth
git checkout tags/1.0.8
sudo python setup.py install

###
# ZeroCloud: ZeroVM middleware for Swift
# Install is from the code on the host, mapped to /zerocloud
cd /zerocloud-root
sudo python setup.py develop

###
# Python system image for ZeroCloud/ZeroVM
sudo mkdir /usr/share/zerovm
cd /usr/share/zerovm
sudo wget -q http://packages.zerovm.org/zerovm-samples/python.tar

###
# DevStack

# Use https:// instead of git:// since the latter might be blocked by
# firewalls whereas HTTPS is pretty much always open.
cat >> ~/.gitconfig <<EOF
[url "https://github"]
        insteadOf = git://github
[url "https://git.openstack"]
	insteadOf = git://git.openstack
EOF

git clone https://github.com/openstack-dev/devstack.git $HOME/devstack
cd $HOME/devstack
git checkout $DEVSTACK_VERSION
cat >> local.conf <<EOF
[[local|localrc]]
ADMIN_PASSWORD=admin
HOST_IP=127.0.0.1
disable_all_services
enable_service mysql s-proxy s-object s-container s-account
# Commit 034fae630cfd652093ef53164a7f9f43bde67336 in Swift
# breaks ZeroCloud, completely and utterly.
# The previous commit works:
SWIFT_BRANCH=ca915156fb2ce4fe4356f54fb2cee7bd01185af5
KEYSTONE_BRANCH=2fc25ff9bb2480d04acae60c24079324d4abe3b0
EOF

# Post-config hook for configuring zerocloud (and swauth) middleware
# for swift. This will get run during ./stack.sh, before services are
# actually started.
# See http://devstack.org/plugins.html for more info on how this works.
cat >> $HOME/devstack/extras.d/89-zerocloud.sh <<EOF
if [[ "\$1" == "stack" && "\$2" == "post-config" ]]; then
    echo_summary "Configuring ZeroCloud middleware for Swift"
    python /vagrant/configure_swift.py
fi
EOF

./stack.sh

###
# Set up users
swauth-prep -K $SWAUTH_SA_KEY
swauth-add-user -A http://127.0.0.1:8080/auth/ -K $SWAUTH_SA_KEY \
    --admin adminacct admin adminpass
swauth-add-user -A http://127.0.0.1:8080/auth/ -K $SWAUTH_SA_KEY \
   demoacct demo demopass

###
# Install Swift Browser

# The version of nodejs from nodesource also included npm
sudo apt-get install nodejs --yes

# Avoid Bower asking "May bower anonymously report usage statistics to
# improve the tool over time?"
cat > $HOME/.bowerrc <<EOF
{
  "analytics": false
}
EOF

git clone https://github.com/zerovm/swift-browser.git $HOME/swift-browser
cd $HOME/swift-browser
npm install

cd app
source /vagrant/adminrc
swift post -r '.r:*' swift-browser
swift upload swift-browser .

STORAGE_URL=$(swift stat -v | grep StorageURL | cut -d ' ' -f 6)
echo "Swift Browser installed at:"
echo "  $STORAGE_URL/swift-browser/index.html"
echo "User: $ST_USER"
echo "Key: $ST_KEY"
