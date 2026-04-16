cmake_minimum_required(VERSION 3.15)
project(FuzzyNamePSI)

# Force C++20 and the modern ABI
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GLIBCXX_USE_CXX11_ABI=1")

# Explicitly add architecture flags that cryptoTools expects
add_compile_options(-maes -msse4.1 -mavx2 -mpclmul)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add these for better compatibility with osuCrypto
add_compile_options(-maes -msse4.1 -mavx2 -mpclmul)
add_definitions(-D_GLIBCXX_USE_CXX11_ABI=1)

set(INSTALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/install")
list(APPEND CMAKE_PREFIX_PATH "${INSTALL_DIR}")

find_package(cryptoTools REQUIRED)
find_package(libOTe REQUIRED)
find_package(volePSI REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread regex)

include_directories(${cryptoTools_INCLUDE_DIRS})
include_directories(${libOTe_INCLUDE_DIRS})
include_directories(${volePSI_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(SOURCES name_encoding.cpp rlc.cpp ass.cpp)
set(LIB_PATH "${INSTALL_DIR}/lib")

# Use the Grouping strategy to force the linker to resolve circular dependencies
set(LINK_STR
    -Wl,--start-group
    ${LIB_PATH}/libvolePSI.a
    ${LIB_PATH}/liblibOTe.a
    ${LIB_PATH}/libcryptoTools.a
    ${LIB_PATH}/libcoproto.a
    ${LIB_PATH}/libmacoro.a
    ${LIB_PATH}/libbitpolymul.a
    ${LIB_PATH}/libsodium.a
    -Wl,--end-group
    Boost::system
    Boost::thread
    pthread
    dl
)

add_executable(local_compute local_compute.cpp ${SOURCES})
target_link_libraries(local_compute 
    -Wl,--start-group
    ${LIB_PATH}/libvolePSI.a
    ${LIB_PATH}/liblibOTe.a
    ${LIB_PATH}/libcryptoTools.a
    ${LIB_PATH}/libcoproto.a
    ${LIB_PATH}/libmacoro.a
    ${LIB_PATH}/libbitpolymul.a
    ${LIB_PATH}/libsodium.a
    -Wl,--end-group
    # List these again just in case
    ${LIB_PATH}/libcryptoTools.a
    ${LIB_PATH}/liblibOTe.a
    Boost::system
    Boost::thread
    pthread
    dl
)

add_executable(ss_psi ss_psi.cpp ${SOURCES})
target_link_libraries(ss_psi ${LINK_STR})