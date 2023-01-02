cmake_minimum_required(VERSION 3.15)

project(MPSU)

add_executable(mpsu_make mpsu.cpp)

find_package(libOTe REQUIRED)

target_link_libraries(mpsu_make oc::libOTe)

find_package(emp-ot)
include_directories(${EMP-OT_INCLUDE_DIRS})
message(${EMP-OT_INCLUDE_DIRS})
find_package(emp-tool)
include_directories(${EMP-TOOL_INCLUDE_DIRS})
find_package(emp-sh2pc)
include_directories(${EMP-SH2PC_INCLUDE_DIRS})

# add_subdirectory(emptool_private_compare-master/emp/)