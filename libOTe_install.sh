#!/bin/bash

# Install libOTe
git submodule update --init

# Checkout correct version
cd libOTe
git submodule update --init

# Build libOTe
python build.py --setup --boost --relic --sodium --bitpolymul
python build.py -- -D ENABLE_RELIC=ON -D ENABLE_ALL_OT=ON -D ENABLE_SODIUM=ON

# install libOTe's packages
python build.py --setup --boost --relic --sodium  --bitpolymul --install
python build.py --install