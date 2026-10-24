local core_sources = {
    "../src/core/error.cpp",
    "../src/core/types.cpp",
    "../src/core/log.cpp",
    "../src/config/config.cpp",
}

target("core_and_config_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++23")
    add_includedirs("../src")
    add_files("units/core_and_config_test.cpp", table.unpack(core_sources))
    add_packages("fmt", "fmtlog", "glaze")
    add_syslinks("pthread")
    add_defines("_GNU_SOURCE")
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror")
    add_tests("default")
target_end()

target("protocol_and_chain_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++23")
    add_includedirs("../src")
    add_files(
        "units/protocol_and_chain_test.cpp",
        "../src/protocol/socket_io.cpp",
        "../src/protocol/tunnel_fsm.cpp",
        "../src/chain/chain_scheduler.cpp",
        table.unpack(core_sources)
    )
    add_packages("fmt", "fmtlog", "glaze")
    add_syslinks("pthread")
    add_defines("_GNU_SOURCE")
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror")
    add_tests("default")
target_end()

target("dns_and_daemon_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++23")
    add_includedirs("../src")
    add_files(
        "units/dns_and_daemon_test.cpp",
        "../src/dns/fake_ip_table.cpp",
        "../src/dns/hosts_cache.cpp",
        "../src/dns/rdns_resolver.cpp",
        "../src/daemon/udp_server.cpp",
        table.unpack(core_sources)
    )
    add_packages("fmt", "fmtlog", "glaze", "c-ares")
    add_syslinks("pthread")
    add_defines("_GNU_SOURCE")
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror")
    add_tests("default")
target_end()

target("hooks_and_cli_test")
    set_kind("binary")
    set_default(false)
    set_group("tests")
    set_languages("c++23")
    add_deps("proxychains-lib")
    add_includedirs("../src")
    add_files(
        "e2e/hooks_and_cli_test.cpp",
        "../src/version.cpp",
        "../src/cli/launcher_main.cpp",
        "../src/protocol/socket_io.cpp",
        "../src/protocol/tunnel_fsm.cpp",
        "../src/chain/chain_scheduler.cpp",
        "../src/dns/fake_ip_table.cpp",
        "../src/dns/hosts_cache.cpp",
        "../src/dns/rdns_resolver.cpp",
        "../src/hooks/hooks.cpp",
        table.unpack(core_sources)
    )
    add_packages("fmt", "fmtlog", "glaze", "c-ares", "cxxopts")
    add_syslinks("dl", "pthread")
    add_defines(
        "_GNU_SOURCE",
        "CXXOPTS_NO_EXCEPTIONS",
        'LIB_DIR="/usr/local/lib"',
        'SYSCONFDIR="/usr/local/etc"',
        'INSTALL_PREFIX="/usr/local"',
        'DLL_NAME="libproxychains.so"',
        "SUPER_SECURE",
        "GN_NODELEN_T=socklen_t",
        "GN_SERVLEN_T=socklen_t",
        "GN_FLAGS_T=int"
    )
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror")
    add_tests("default", {runenvs = {PROXYCHAINS_PROXY_URL = "socks5://127.0.0.1:1080", PROXYCHAINS_QUIET_MODE = "1"}})
target_end()
