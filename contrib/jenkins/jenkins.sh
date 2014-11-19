#!/bin/bash

WORKSPACE=$HOME/workspace
DEPS="git python-pip python-dev libffi-dev"

sudo apt-get update
sudo apt-get install --yes $DEPS
sudo pip install tox

rsync -az --exclude=contrib/jenkins/.* /jenkins/ $WORKSPACE
cd $WORKSPACE

# Jenkins can now run test commands
tox
sudo cp junit.xml /jenkins
git clean -fdx
