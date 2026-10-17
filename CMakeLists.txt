cmake_minimum_required(VERSION 3.20)
project(AuthServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Drogon CONFIG REQUIRED)
find_package(PostgreSQL REQUIRED)
find_package(unofficial-argon2 CONFIG REQUIRED)

add_executable(AuthServer
        src/main.cpp
)

target_link_libraries(AuthServer
        PRIVATE
        Drogon::Drogon
        PostgreSQL::PostgreSQL
        unofficial::argon2::libargon2
        bcrypt
)
