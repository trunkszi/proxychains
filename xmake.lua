set_project("proxychains")
set_languages("c++23")

add_rules("mode.debug", "mode.release")

set_version("0.0.1")

add_requires("fmt 11.1.3", {system = false, configs = {pic = true}})
add_requires("fmtlog", {system = false, configs = {pic = true}})
add_requires("glaze", {system = false, configs = {pic = true, ssl = false}})
add_requires("c-ares", {system = false, configs = {pic = true}})
add_requires("cxxopts", {system = false})

includes("@builtin/check")

---------------------------------------------------------------------------
-- options
---------------------------------------------------------------------------
option("super_secure")
    set_default(true)
    set_showmenu(true)
    set_description("Enable CVE-2015-3887 protection (disable CWD lib search)")
option_end()

option("lto")
    set_default(false)
    set_showmenu(true)
    set_description("Enable Link Time Optimization")
option_end()

option("hookmethod")
    set_default("auto")
    set_showmenu(true)
    set_description("Hook method for macOS: auto, dlsym, dyld")
    set_values("auto", "dlsym", "dyld")
option_end()

option("fat_binary")
    set_default(false)
    set_showmenu(true)
    set_description("Build fat binary on macOS (x86_64 + arm64)")
option_end()

---------------------------------------------------------------------------
-- shared library: libproxychains.so / libproxychains.dylib
---------------------------------------------------------------------------
target("proxychains-lib")
    set_kind("shared")
    set_basename("proxychains")

    add_includedirs("src")
    add_files(
        "src/version.cpp",
        "src/core/error.cpp",
        "src/core/types.cpp",
        "src/core/log.cpp",
        "src/config/config.cpp",
        "src/protocol/socket_io.cpp",
        "src/protocol/tunnel_fsm.cpp",
        "src/chain/chain_scheduler.cpp",
        "src/dns/fake_ip_table.cpp",
        "src/dns/hosts_cache.cpp",
        "src/dns/rdns_resolver.cpp",
        "src/hooks/hooks.cpp"
    )

    add_packages("fmt", "fmtlog", "glaze", "c-ares")

    add_defines("_GNU_SOURCE")
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror", "-pipe", "-fPIC")

    add_defines(
        'LIB_DIR="/usr/local/lib"',
        'SYSCONFDIR="/usr/local/etc"',
        'INSTALL_PREFIX="/usr/local"'
    )

    if has_config("super_secure") then
        add_defines("SUPER_SECURE")
    end

    if has_config("lto") then
        set_policy("build.optimization.lto", true)
    end

    if is_plat("macosx") then
        add_defines("IS_MAC=1", 'DLL_NAME="libproxychains.dylib"')
        add_syslinks("pthread")
    elseif is_plat("linux") then
        add_defines('DLL_NAME="libproxychains.so"')
        add_syslinks("dl", "pthread")
        add_ldflags("-Wl,--no-as-needed")
    elseif is_plat("bsd") then
        add_defines("IS_BSD", 'DLL_NAME="libproxychains.so"')
        add_syslinks("pthread")
    else
        add_defines('DLL_NAME="libproxychains.so"')
    end

    set_configdir("src")
    add_configfiles("src/version.h.in")
    set_configvar("VERSION", "0.0.1", {quote = false})

    on_load(function (target)
        try {function ()
            if os.isdir(".git") or os.isfile(".git") then
                local v = os.iorun("git describe --tags --match 'v[0-9]*' 2>/dev/null")
                if v then
                    target:set("configvar", "VERSION", v:trim():gsub("^v", ""):gsub("%-", "-git-", 1))
                end
            end
        end}
    end)

    on_config(function (target)
        local gn_sigs = {
            {"socklen_t", "socklen_t", "int",
             '#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include <netdb.h>\nint getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);int main() {return 0;}'},
            {"socklen_t", "socklen_t", "unsigned",
             '#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include <netdb.h>\nint getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, unsigned);int main() {return 0;}'},
            {"socklen_t", "size_t", "int",
             '#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include <netdb.h>\nint getnameinfo(const struct sockaddr *, socklen_t, char *, socklen_t, char *, size_t, int);int main() {return 0;}'},
            {"size_t", "size_t", "int",
             '#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n#include <netdb.h>\nint getnameinfo(const struct sockaddr *, socklen_t, char *, size_t, char *, size_t, int);int main() {return 0;}'},
        }
        for _, sig in ipairs(gn_sigs) do
            if target:check_csnippets({test = sig[4]}) then
                target:add("defines", "GN_NODELEN_T=" .. sig[1], "GN_SERVLEN_T=" .. sig[2], "GN_FLAGS_T=" .. sig[3])
                return
            end
        end
        target:add("defines", "GN_NODELEN_T=socklen_t", "GN_SERVLEN_T=socklen_t", "GN_FLAGS_T=int")
    end)

    on_install(function (target)
        local installdir = target:installdir()
        os.mkdir(path.join(installdir, "lib"))
        os.cp(target:targetfile(), path.join(installdir, "lib/"))
    end)
target_end()

---------------------------------------------------------------------------
-- executable: proxychains
---------------------------------------------------------------------------
target("proxychains-cli")
    set_kind("binary")
    set_basename("proxychains")

    add_includedirs("src")
    add_files(
        "src/version.cpp",
        "src/core/error.cpp",
        "src/core/types.cpp",
        "src/core/log.cpp",
        "src/config/config.cpp",
        "src/cli/launcher_main.cpp"
    )

    add_packages("fmt", "fmtlog", "glaze", "cxxopts")

    add_defines("_GNU_SOURCE", "CXXOPTS_NO_EXCEPTIONS")
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror", "-pipe")

    add_deps("proxychains-lib")

    add_defines(
        'LIB_DIR="/usr/local/lib"',
        'SYSCONFDIR="/usr/local/etc"'
    )

    if has_config("super_secure") then
        add_defines("SUPER_SECURE")
    end

    if has_config("lto") then
        set_policy("build.optimization.lto", true)
    end

    if is_plat("macosx") then
        add_defines('DLL_NAME="libproxychains.dylib"')
        add_syslinks("dl", "pthread")
    else
        add_defines('DLL_NAME="libproxychains.so"')
        if is_plat("linux") then
            add_syslinks("dl", "pthread")
        end
    end

    if is_plat("macosx") and has_config("fat_binary") then
        add_cxxflags("-arch arm64", "-arch x86_64")
        add_ldflags("-arch arm64", "-arch x86_64")
    end

    if is_plat("linux") then
        add_rpathdirs("$ORIGIN/../lib")
    elseif is_plat("macosx") then
        add_rpathdirs("@executable_path/../lib")
    end

    on_install(function (target)
        local installdir = target:installdir()
        local bindir = path.join(installdir, "bin")
        os.mkdir(bindir)
        os.cp(target:targetfile(), bindir)

        local sysconfdir = path.join(installdir, "etc")
        os.mkdir(sysconfdir)
        local conffile = path.join(sysconfdir, "proxychains.yaml")
        if not os.isfile(conffile) then
            os.cp("configs/proxychains.yaml", conffile)
        end

        local zshdir = path.join(installdir, "share/zsh/site-functions")
        if os.isfile("completions/zsh/_proxychains") then
            os.mkdir(zshdir)
            os.cp("completions/zsh/_proxychains", zshdir)
        end

        local bashdir = path.join(installdir, "share/bash-completion/completions")
        if os.isfile("completions/bash/proxychains") then
            os.mkdir(bashdir)
            os.cp("completions/bash/proxychains", bashdir)
        end
    end)
target_end()

---------------------------------------------------------------------------
-- executable: proxychains-daemon (optional, not built by default)
---------------------------------------------------------------------------
target("proxychains-daemon")
    set_kind("binary")
    set_default(false)

    add_includedirs("src")
    add_files(
        "src/core/error.cpp",
        "src/core/types.cpp",
        "src/core/log.cpp",
        "src/dns/fake_ip_table.cpp",
        "src/daemon/udp_server.cpp",
        "src/daemon/daemon_main.cpp"
    )

    add_packages("fmt", "fmtlog", "c-ares", "cxxopts")
    add_syslinks("pthread")
    add_defines("_GNU_SOURCE", "CXXOPTS_NO_EXCEPTIONS")
    add_cxxflags("-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Wshadow", "-Werror", "-pipe")

    if has_config("lto") then
        set_policy("build.optimization.lto", true)
    end

    on_install(function (target)
        local installdir = target:installdir()
        os.mkdir(path.join(installdir, "bin"))
        os.cp(target:targetfile(), path.join(installdir, "bin/"))
    end)
target_end()

---------------------------------------------------------------------------
-- tests (not built by default, use: xmake build -g tests)
---------------------------------------------------------------------------
includes("tests")
