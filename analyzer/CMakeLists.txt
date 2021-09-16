add_library(analyzer_lib
    src/analyzer.c
    src/session_tree.c)

add_library(Analyzer::library ALIAS analyzer_lib)

add_library(analyzer_lib_interface INTERFACE)
add_library(Analyzer::interface ALIAS analyzer_lib_interface)

target_include_directories(analyzer_lib_interface
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(analyzer_lib
    PUBLIC
    Analyzer::interface)        

add_executable(analyzer
    src/main.c)    

include(FindPCAP.cmake)

target_link_libraries(analyzer
    PRIVATE
        Analyzer::library
        ${PCAP_LIBRARY})

