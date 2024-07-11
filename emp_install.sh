#!/bin/bash

# Download emp-toolkit libraries
echo "Downloading emp-toolkit libraries"
echo "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
cd emp
python download.py --deps --tool --ot --sh2pc
# modify emp-toolkit libraries so it is compatible with libOTe
echo "Modifying emp-toolkit libraries"
echo "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
python modify_block.py --directory emp-tool
python modify_block.py --directory emp-ot
python modify_block.py --directory emp-sh2pc
#change c++11 to c++14
python modify_cmake.py --file emp-tool/cmake/emp-base.cmake

# Install emp-toolkit libraries
echo "Installing emp-toolkit libraries"
echo "python install.py --deps --tool --ot --sh2pc"
python install.py --deps --tool --ot --sh2pc


