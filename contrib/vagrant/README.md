## Installation

### Ubuntu Linux 12.04

1. Install VirtualBox:

    `sudo apt-get install virtualbox`


2. Install the latest version of Vagrant:

```bash
# 64-bit
wget https://dl.bintray.com/mitchellh/vagrant/vagrant_1.6.3_x86_64.deb
sudo dpkg -i vagrant_1.6.3_x86_64.deb
# 32-bit
wget https://dl.bintray.com/mitchellh/vagrant/vagrant_1.6.3_i686.deb
sudo dpkg -i vagrant_1.6.3_i686.deb
```

For a list of all releases of Vagrant, see https://dl.bintray.com/mitchellh/vagrant/.

3. Change into this directory (the one with `Vagrantfile`).

4. Run Vagrant:

    `vagrant up`


### OSX

1. Download and install VirtualBox and Vagrant from .dmgs. See https://www.virtualbox.org/wiki/Downloads
   and https://www.vagrantup.com/downloads.

2. Change into this directory (the one with `Vagrantfile`).

3. Run Vagrant:

    `vagrant up`
