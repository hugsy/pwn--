include(FetchContent)

FetchContent_Declare(
    Catch2
    URL https://github.com/catchorg/Catch2/archive/refs/tags/v3.4.0.zip
    URL_HASH MD5=c426e77d4ee0055410bc930182959ae5
)

FetchContent_MakeAvailable(Catch2)

add_library(PWN::Deps::Catch2 ALIAS Catch2)
