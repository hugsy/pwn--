include(FetchContent)

FetchContent_Declare(
    Deps_PhNt
    GIT_REPOSITORY https://github.com/winsiderss/phnt.git
    GIT_TAG fc1f96ee976635f51faa89896d1d805eb0586350
)
FetchContent_MakeAvailable(Deps_PhNt)

add_library(Deps_PhNt INTERFACE)
add_library(PWN::Deps::PHNT ALIAS Deps_PhNt)
target_include_directories(Deps_PhNt INTERFACE ${deps_phnt_SOURCE_DIR})
target_link_libraries(Deps_PhNt INTERFACE "ntdll.lib")
