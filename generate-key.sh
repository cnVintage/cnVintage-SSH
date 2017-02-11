#!/bin/bash

if [ -e ./build/ssh_host_rsa_key ]; then
  echo "Keys already exist, skipping..."
  exit 0
else
  mkdir -p build && cd build
  ssh-keygen -f ssh_host_rsa_key -N '' -t rsa
  ssh-keygen -f ssh_host_dsa_key -N '' -t dsa
fi
