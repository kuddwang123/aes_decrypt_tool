cmake_minimum_required(VERSION 2.8)


project( decrypt_pro )

include_directories("/home/wangqing/work_space/hj_workspace/src/thirdparty/include")

link_directories("/home/wangqing/work_space/hj_workspace/src/thirdparty/platforms/amd64/")
# include_directories("/thirdparty/thirdparty/include")

# link_directories("/thirdparty/thirdparty/platforms/aarch64-linux-gnu")
# set( CMAKE_BUILD_TYPE Release )
set( CMAKE_CXX_FLAGS "-std=c++14 -g" )
add_executable(decrypt_pro src/main.cpp)
target_link_libraries(decrypt_pro -lcrypto -lbase64)
