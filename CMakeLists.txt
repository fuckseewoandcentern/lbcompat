cmake_minimum_required(VERSION 3.16)

# /usr/bin/c++ is clang on this image and does not find libstdc++.
if(NOT DEFINED CMAKE_CXX_COMPILER AND NOT DEFINED ENV{CXX})
    set(CMAKE_CXX_COMPILER g++)
endif()

project(lbcompat LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(Vulkan REQUIRED)
find_package(X11 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(DBUS REQUIRED dbus-1)

add_library(lbcompat STATIC
    src/exec.cpp
    src/dbt.cpp
    src/shim_stub.cpp
    src/macho.cpp
    src/runtime.cpp
    src/objc.cpp
    src/metal.cpp
    src/mpris.cpp
)
target_include_directories(lbcompat PUBLIC include PRIVATE src ${DBUS_INCLUDE_DIRS})
target_compile_options(lbcompat PRIVATE -Wall -Wextra -Wno-unused-function -Wno-unused-parameter)
target_link_libraries(lbcompat PUBLIC Threads::Threads Vulkan::Vulkan X11::X11 ${DBUS_LIBRARIES} dl)

add_executable(lbcompat_run src/main.cpp)
target_link_libraries(lbcompat_run PRIVATE lbcompat)
set_target_properties(lbcompat_run PROPERTIES OUTPUT_NAME lbcompat)

add_executable(lb-mpris-bridge src/bridge_main.cpp)
target_link_libraries(lb-mpris-bridge PRIVATE lbcompat)

function(lb_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE lbcompat)
    target_include_directories(${name} PRIVATE src)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wno-unused-parameter)
    target_link_options(${name} PRIVATE -rdynamic)
endfunction()

lb_test(test_arm64)
lb_test(test_macho)
lb_test(test_mpris)
lb_test(test_metal)
lb_test(test_boot)
