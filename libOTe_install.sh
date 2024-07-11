#!/bin/bash

# Install libOTe
git submodule update --init

# Checkout correct version
cd libOTe
git checkout -b v1.5.4 2363505431f744539027a873c2536b9ae3630ff7
git submodule update --init

# Build libOTe
python build.py --setup --boost --relic --sodium
python build.py -- -D ENABLE_RELIC=ON -D ENABLE_ALL_OT=ON -D ENABLE_SODIUM=ON

# install libOTe's packages
python build.py --setup --boost --relic --sodium --install
python build.py --install