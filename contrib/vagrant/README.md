## Installation

### Ubuntu Linux 12.04

1. Install VirtualBox and Vagrant:

        sudo apt-get install virtualbox vagrant

2. Add a 64-bit Ubuntu 12.04 LTS box to Vagrant:

        vagrant box add hashicorp/precise64 http://files.vagrantup.com/precise64.box

3. Change into this directory (the one with `Vagrantfile`).

4. Run Vagrant:

        vagrant up


### OSX

1. Download and install VirtualBox and Vagrant from .dmgs. See https://www.virtualbox.org/wiki/Downloads
   and https://www.vagrantup.com/downloads.

2. Change into this directory (the one with `Vagrantfile`).

3. Run Vagrant:

        vagrant up


## Client configuration

You can use `python-swiftclient` and `zvm/zpm` with this vagrant box. To set
the needed environment variables, just do:

    source adminrc


## Restarting DevStack and ZeroCloud

First, log in to the vagrant box:

    vagrant ssh

Next, we need to terminate all of the DevStack processes. The first time you do
this, you need to use a little brute force. First, run `rejoin_stack.sh`:

```bash
cd $HOME/devstack
./rejoin_stack.sh
```

This will put you into a screen session. To terminate DevStack,
press 'ctrl+a backslash', then 'y' to confirm. NOTE: The first time you restart
DevStack after provisioning the machine, not all of the Swift processes will be
killed. A little brute force is needed:

    ps ax | grep [s]wift | awk '{print $1}' | xargs kill

Now restart DevStack:

```bash
cd $HOME/devstack
./rejoin_stack.sh
```

If you make configuration changes after this first DevStack restart, subsequent
restarts are easier. Run `rejoin_stack.sh` as above, press 'ctrl+a backslash',
'y' to confirm, then run `rejoin_stack.sh` again.

To log out of the vagrant box and keep everything running, press 'ctrl+a d' to
detach from the screen session. You can now log out of the box ('ctrl+d').

[restart]: #restarting-devstack-and-zerocloud

## Testing the vagrant development environment

Once everything is set up, it's a good idea to test that ZeroVM and ZeroCloud
are functioning properly. First, you need to install `pip`: see
https://pip.pypa.io/en/latest/installing.html.

Next, you'll need to install `tox`, for running the tests:

```bash
$ pip install tox
```

From the same directory as the `Vagrantfile` (and this README), execute the
tests:

```bash
$ tox
```
