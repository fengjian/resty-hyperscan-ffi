project(hs_scan)

include(FindPkgConfig)
pkg_check_modules(HS REQUIRED libhs)

cmake_minimum_required(VERSION 3.0.0)

find_package(OpenMP)
if (OPENMP_FOUND)
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
	set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
	set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()


set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")
set(CMAKE_CXX_FLAGS_DEBUG          "-g -DDEBUG")
set(CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-O4 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")


add_executable(hs_scan hs_scan.cpp)
add_library(hscan SHARED hs_scan.cpp)

target_link_libraries(hs_scan ${HS_LIBRARIES})
target_include_directories(hs_scan PUBLIC ${HS_INCLUDE_DIRS})
target_compile_options(hs_scan PUBLIC ${HS_CFLAGS_OTHER})

target_link_libraries(hscan ${HS_LIBRARIES})
target_include_directories(hscan PUBLIC ${HS_INCLUDE_DIRS})
target_compile_options(hscan PUBLIC ${HS_CFLAGS_OTHER})
