cmake_minimum_required(VERSION 3.21)

set(SSH2HTTP_VERSION_MAJOR 0)
set(SSH2HTTP_VERSION_MINOR 0)
set(SSH2HTTP_VERSION_PATCH 1)
project(ssh2http 
    LANGUAGES CXX C 
    VERSION ${SSH2HTTP_VERSION_MAJOR}.${SSH2HTTP_VERSION_MINOR}.${SSH2HTTP_VERSION_PATCH})
# edit the following settings as you desire
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_EXTENSION OFF)
add_compile_options(-Wfatal-errors)

# edit the following line to add your cmake modules
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake_modules)
# options flags to turn on/off unit tests and benchmarks
# edit the following line to add your dependencies
find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Threads REQUIRED)

file(GLOB EXECUTABLE_SRC "ssh2http/*.cpp")
add_executable(${PROJECT_NAME} ${EXECUTABLE_SRC})
target_include_directories(${PROJECT_NAME} PRIVATE
    ${PROJECT_SOURCE_DIR}/ssh2http)

# edit the following line to link your dependencies libraries
target_link_libraries(${PROJECT_NAME}
    PRIVATE
        Boost::program_options
        Threads::Threads)
# install settings
include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
# auto versioning reads from header.h to get versionstring
message(STATUS "current ssh2http version: ${SSH2HTTP_VERSION_MAJOR}.${SSH2HTTP_VERSION_MINOR}.${SSH2HTTP_VERSION_PATCH}")
set(CPACK_PACKAGE_VERSION_MAJOR ${SSH2HTTP_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${SSH2HTTP_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${SSH2HTTP_VERSION_PATCH})
# cpack settings, edit the following to pack up as you desire
if(UNIX)
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_GENERATOR "ZIP")
endif()
set(CPACK_PACKAGE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/packages)
include(CPack)
