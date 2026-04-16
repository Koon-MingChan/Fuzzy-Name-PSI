#!/bin/bash
# setup_deps.sh

# 1. Create a local folder for libraries
mkdir -p extern
cd extern

# 2. Clone from the correct ladnir repo
if [ ! -d "volepsi" ]; then
    git clone --recursive https://github.com/ladnir/volepsi.git
fi
cd volepsi

# 3. Build and install using explicit CMake definitions
# We replace --boost and --sodium with the defines the script expects
python3 build.py --setup --install=../../install -DVOLE_PSI_ENABLE_BOOST=ON -DVOLE_PSI_ENABLE_SODIUM=ON -DVOLE_PSI_ENABLE_AVX2=ON

echo "-------------------------------------------------------"
echo "Dependencies should now be in: ~/dev/Fuzzy-Name-PSI/install"
echo "-------------------------------------------------------"