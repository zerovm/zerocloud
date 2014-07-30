## Installation

### Ubuntu Linux 12.04

1. Install VirtualBox:

        sudo apt-get install virtualbox


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

        vagrant up

5. Once everything is set up, you'll need to restart Devstack in order for the
   ZeroCloud configurations to take effect. See [Restarting DevStack and
   ZeroCloud][restart] below.


### OSX

1. Download and install VirtualBox and Vagrant from .dmgs. See https://www.virtualbox.org/wiki/Downloads
   and https://www.vagrantup.com/downloads.

2. Change into this directory (the one with `Vagrantfile`).

3. Run Vagrant:

        vagrant up

4. Once everything is set up, you'll need to restart DevStack in order for the
   ZeroCloud configurations to take effect. See [Restarting DevStack and
   ZeroCloud][restart] below.


## Client configuration

You can use `python-swiftclient` and `zvm/zpm` with this vagrant box. To set
the needed environment variables, just do:

    source zerocloudrc


## Restarting DevStack and ZeroCloud

First, log in to the vagrant box:

`vagrant ssh`

Next, we need to terminate DevStack:

```bash
cd $HOME/devstack
./rejoin_stack.sh
```

This will put you into a screen session. To terminate DevStack,
press 'ctrl+a backslash', then 'y' to confirm.

To start DevStack again, type `./rejoin-stack.sh`. If you want to detach
from this screen session (and return to the vagrant box shell), press
'ctrl+a d'. You can log out ('ctrl+d') of the box now if you want and
everything will still be running.

[restart]: #restarting-devstack-and-zerocloud
