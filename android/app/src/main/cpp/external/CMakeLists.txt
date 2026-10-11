project(external)

add_subdirectory(fmt)
add_subdirectory(system_properties)
# TrustAttestor links a deliberately slim libcxx.a without std::locale.
# Disable fmt's locale-dependent formatting to avoid unresolved locale symbols.
target_compile_definitions(fmt-header-only INTERFACE
        FMT_STATIC_THOUSANDS_SEPARATOR=1
        FMT_USE_FLOAT=0
        FMT_USE_DOUBLE=1
        FMT_USE_LONG_DOUBLE=0
        FMT_USE_LOCALE=0
)

add_subdirectory(musl)
link_libraries(musl)
