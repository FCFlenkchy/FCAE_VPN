cmake_minimum_required(VERSION 3.10)
project(hev-socks5-tunnel C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Default to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ── Source files ────────────────────────────────────────────────────────

set(MAIN_SOURCES
    src/hev-main.c
    src/hev-config.c
    src/hev-jni.c
    src/hev-mapped-dns.c
    src/hev-socks5-session.c
    src/hev-socks5-session-tcp.c
    src/hev-socks5-session-udp.c
    src/hev-socks5-tunnel.c
    src/hev-tunnel-linux.c
    src/hev-tunnel-windows.c
    src/hev-tunnel-freebsd.c
    src/hev-tunnel-macos.c
    src/hev-tunnel-netbsd.c
    src/misc/hev-exec.c
    src/misc/hev-list.c
    src/misc/hev-logger.c
    src/misc/hev-ring-buffer.c
    src/misc/hev-utils.c
    src/misc/hev-wintun.c
)

set(CORE_SOURCES
    src/core/src/hev-rbtree.c
    src/core/src/hev-socks5.c
    src/core/src/hev-socks5-authenticator.c
    src/core/src/hev-socks5-client.c
    src/core/src/hev-socks5-client-tcp.c
    src/core/src/hev-socks5-client-udp.c
    src/core/src/hev-socks5-logger.c
    src/core/src/hev-socks5-misc.c
    src/core/src/hev-socks5-server.c
    src/core/src/hev-socks5-tcp.c
    src/core/src/hev-socks5-udp.c
    src/core/src/hev-socks5-user.c
)

set(YAML_SOURCES
    third-part/yaml/src/api.c
    third-part/yaml/src/dumper.c
    third-part/yaml/src/emitter.c
    third-part/yaml/src/loader.c
    third-part/yaml/src/parser.c
    third-part/yaml/src/reader.c
    third-part/yaml/src/scanner.c
    third-part/yaml/src/writer.c
)

set(LWIP_SOURCES
    third-part/lwip/src/api/api_lib.c
    third-part/lwip/src/api/api_msg.c
    third-part/lwip/src/api/err.c
    third-part/lwip/src/api/if_api.c
    third-part/lwip/src/api/netbuf.c
    third-part/lwip/src/api/netdb.c
    third-part/lwip/src/api/netifapi.c
    third-part/lwip/src/api/sockets.c
    third-part/lwip/src/api/tcpip.c
    third-part/lwip/src/core/altcp.c
    third-part/lwip/src/core/altcp_alloc.c
    third-part/lwip/src/core/altcp_tcp.c
    third-part/lwip/src/core/def.c
    third-part/lwip/src/core/dns.c
    third-part/lwip/src/core/inet_chksum.c
    third-part/lwip/src/core/init.c
    third-part/lwip/src/core/ip.c
    third-part/lwip/src/core/mem.c
    third-part/lwip/src/core/memp.c
    third-part/lwip/src/core/netif.c
    third-part/lwip/src/core/pbuf.c
    third-part/lwip/src/core/raw.c
    third-part/lwip/src/core/stats.c
    third-part/lwip/src/core/sys.c
    third-part/lwip/src/core/tcp.c
    third-part/lwip/src/core/tcp_in.c
    third-part/lwip/src/core/tcp_out.c
    third-part/lwip/src/core/timeouts.c
    third-part/lwip/src/core/udp.c
    third-part/lwip/src/core/ipv4/acd.c
    third-part/lwip/src/core/ipv4/autoip.c
    third-part/lwip/src/core/ipv4/dhcp.c
    third-part/lwip/src/core/ipv4/etharp.c
    third-part/lwip/src/core/ipv4/icmp.c
    third-part/lwip/src/core/ipv4/igmp.c
    third-part/lwip/src/core/ipv4/ip4.c
    third-part/lwip/src/core/ipv4/ip4_addr.c
    third-part/lwip/src/core/ipv4/ip4_frag.c
    third-part/lwip/src/core/ipv6/dhcp6.c
    third-part/lwip/src/core/ipv6/ethip6.c
    third-part/lwip/src/core/ipv6/icmp6.c
    third-part/lwip/src/core/ipv6/inet6.c
    third-part/lwip/src/core/ipv6/ip6.c
    third-part/lwip/src/core/ipv6/ip6_addr.c
    third-part/lwip/src/core/ipv6/ip6_frag.c
    third-part/lwip/src/core/ipv6/mld6.c
    third-part/lwip/src/core/ipv6/nd6.c
    third-part/lwip/src/netif/bridgeif.c
    third-part/lwip/src/netif/bridgeif_fdb.c
    third-part/lwip/src/netif/ethernet.c
    third-part/lwip/src/netif/lowpan6.c
    third-part/lwip/src/netif/lowpan6_ble.c
    third-part/lwip/src/netif/lowpan6_common.c
    third-part/lwip/src/netif/slipif.c
    third-part/lwip/src/netif/zepif.c
    third-part/lwip/src/netif/ppp/auth.c
    third-part/lwip/src/netif/ppp/ccp.c
    third-part/lwip/src/netif/ppp/chap-md5.c
    third-part/lwip/src/netif/ppp/chap-new.c
    third-part/lwip/src/netif/ppp/chap_ms.c
    third-part/lwip/src/netif/ppp/demand.c
    third-part/lwip/src/netif/ppp/eap.c
    third-part/lwip/src/netif/ppp/ecp.c
    third-part/lwip/src/netif/ppp/eui64.c
    third-part/lwip/src/netif/ppp/fsm.c
    third-part/lwip/src/netif/ppp/ipcp.c
    third-part/lwip/src/netif/ppp/ipv6cp.c
    third-part/lwip/src/netif/ppp/lcp.c
    third-part/lwip/src/netif/ppp/magic.c
    third-part/lwip/src/netif/ppp/mppe.c
    third-part/lwip/src/netif/ppp/multilink.c
    third-part/lwip/src/netif/ppp/ppp.c
    third-part/lwip/src/netif/ppp/pppapi.c
    third-part/lwip/src/netif/ppp/pppcrypt.c
    third-part/lwip/src/netif/ppp/pppoe.c
    third-part/lwip/src/netif/ppp/pppol2tp.c
    third-part/lwip/src/netif/ppp/pppos.c
    third-part/lwip/src/netif/ppp/upap.c
    third-part/lwip/src/netif/ppp/utils.c
    third-part/lwip/src/netif/ppp/vj.c
    third-part/lwip/src/netif/ppp/polarssl/arc4.c
    third-part/lwip/src/netif/ppp/polarssl/des.c
    third-part/lwip/src/netif/ppp/polarssl/md4.c
    third-part/lwip/src/netif/ppp/polarssl/md5.c
    third-part/lwip/src/netif/ppp/polarssl/sha1.c
    third-part/lwip/src/ports/lib/mem.c
)

# Platform-specific lwip sources
if(UNIX)
    list(APPEND LWIP_SOURCES
        third-part/lwip/src/ports/unix/lib/perf.c
        third-part/lwip/src/ports/unix/lib/sys_arch.c
        third-part/lwip/src/ports/unix/netif/fifo.c
        third-part/lwip/src/ports/unix/netif/list.c
        third-part/lwip/src/ports/unix/netif/pcapif.c
        third-part/lwip/src/ports/unix/netif/sio.c
        third-part/lwip/src/ports/unix/netif/tapif.c
    )
elseif(WIN32)
    list(APPEND LWIP_SOURCES
        third-part/lwip/src/ports/win32/lib/sys_arch.c
        third-part/lwip/src/ports/win32/netif/sio.c
    )
endif()

# hev-task-system sources (excluding apps/ and tests/)
set(TASK_SOURCES
    third-part/hev-task-system/src/kern/aide/hev-task-aide.c
    third-part/hev-task-system/src/kern/core/hev-task-system.c
    third-part/hev-task-system/src/kern/core/hev-task-system-schedule.c
    third-part/hev-task-system/src/kern/task/hev-task.c
    third-part/hev-task-system/src/kern/task/hev-task-call.c
    third-part/hev-task-system/src/kern/task/hev-task-executer.c
    third-part/hev-task-system/src/kern/task/hev-task-stack-heap.c
    third-part/hev-task-system/src/kern/task/hev-task-stack-mmap.c
    third-part/hev-task-system/src/kern/time/hev-task-timer.c
    third-part/hev-task-system/src/kern/sync/hev-task-cond.c
    third-part/hev-task-system/src/kern/sync/hev-task-mutex.c
    third-part/hev-task-system/src/kern/itc/hev-task-channel.c
    third-part/hev-task-system/src/kern/itc/hev-task-channel-select.c
    third-part/hev-task-system/src/lib/dns/hev-task-dns.c
    third-part/hev-task-system/src/lib/dns/hev-task-dns-proxy.c
    third-part/hev-task-system/src/lib/io/basic/hev-task-io.c
    third-part/hev-task-system/src/lib/io/buffer/hev-circular-buffer.c
    third-part/hev-task-system/src/lib/io/pipe/hev-task-io-pipe.c
    third-part/hev-task-system/src/lib/io/poll/hev-task-io-poll.c
    third-part/hev-task-system/src/lib/io/socket/hev-task-io-socket.c
    # hev-list.c removed (duplicate of src/misc/hev-list.c in MAIN_SOURCES)
    third-part/hev-task-system/src/lib/misc/hev-debugger.c
    third-part/hev-task-system/src/lib/misc/hev-task-stack-detector.c
    third-part/hev-task-system/src/lib/object/hev-object.c
    third-part/hev-task-system/src/lib/object/hev-object-atomic.c
    # hev-rbtree.c removed (duplicate of src/core/src/hev-rbtree.c in CORE_SOURCES)
    third-part/hev-task-system/src/lib/rbtree/hev-rbtree-cached.c
    third-part/hev-task-system/src/mem/api/hev-memory-allocator-api.c
    third-part/hev-task-system/src/mem/base/hev-memory-allocator.c
    third-part/hev-task-system/src/mem/simple/hev-memory-allocator-simple.c
    third-part/hev-task-system/src/mem/slice/hev-memory-allocator-slice.c
)

# Platform-specific IO reactor
if(UNIX)
    list(APPEND TASK_SOURCES
        third-part/hev-task-system/src/kern/io/hev-task-io-reactor-epoll.c
    )
    if(APPLE)
        list(APPEND TASK_SOURCES
            third-part/hev-task-system/src/kern/io/hev-task-io-reactor-kqueue.c
        )
    endif()
elseif(WIN32)
    list(APPEND TASK_SOURCES
        third-part/hev-task-system/src/kern/io/hev-task-io-reactor-iocp.c
    )
endif()

# ── Assembly source (task execute) ──────────────────────────────────────
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    enable_language(ASM)
    list(APPEND TASK_SOURCES third-part/hev-task-system/src/arch/x86/hev-task-execute-x86_64.s)
    set_source_files_properties(
        third-part/hev-task-system/src/arch/x86/hev-task-execute-x86_64.s
        PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp"
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i486|i586|i686|x86")
    enable_language(ASM)
    list(APPEND TASK_SOURCES third-part/hev-task-system/src/arch/x86/hev-task-execute-x86.s)
    set_source_files_properties(
        third-part/hev-task-system/src/arch/x86/hev-task-execute-x86.s
        PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp"
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64")
    enable_language(ASM)
    list(APPEND TASK_SOURCES third-part/hev-task-system/src/arch/arm/hev-task-execute-aarch64.s)
    set_source_files_properties(
        third-part/hev-task-system/src/arch/arm/hev-task-execute-aarch64.s
        PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp"
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    enable_language(ASM)
    list(APPEND TASK_SOURCES third-part/hev-task-system/src/arch/arm/hev-task-execute-arm.s)
    set_source_files_properties(
        third-part/hev-task-system/src/arch/arm/hev-task-execute-arm.s
        PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp"
    )
endif()

# ── Combine all sources ─────────────────────────────────────────────────

set(ALL_SOURCES
    ${MAIN_SOURCES}
    ${CORE_SOURCES}
    ${YAML_SOURCES}
    ${LWIP_SOURCES}
    ${TASK_SOURCES}
)

# ── Executable ──────────────────────────────────────────────────────────

add_executable(hev-socks5-tunnel ${ALL_SOURCES})

# ── Include directories ─────────────────────────────────────────────────

target_include_directories(hev-socks5-tunnel PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/misc
    ${CMAKE_SOURCE_DIR}/src/core/include
    ${CMAKE_SOURCE_DIR}/third-part/yaml/include
    ${CMAKE_SOURCE_DIR}/third-part/wintun/include
    ${CMAKE_SOURCE_DIR}/third-part/lwip/src/include
    ${CMAKE_SOURCE_DIR}/third-part/lwip/src/ports/include
    ${CMAKE_SOURCE_DIR}/third-part/hev-task-system/include
    ${CMAKE_SOURCE_DIR}/third-part/hev-task-system/src
)

# Platform-specific lwip port includes
if(UNIX)
    target_include_directories(hev-socks5-tunnel PRIVATE
        ${CMAKE_SOURCE_DIR}/third-part/lwip/src/ports/unix/include
    )
elseif(WIN32)
    target_include_directories(hev-socks5-tunnel PRIVATE
        ${CMAKE_SOURCE_DIR}/third-part/lwip/src/ports/win32/include
    )
endif()

# ── Defines ─────────────────────────────────────────────────────────────

target_compile_definitions(hev-socks5-tunnel PRIVATE
    COMMIT_ID="unknown"
    YAML_VERSION_STRING="0.2.5"
    YAML_VERSION_MAJOR=0
    YAML_VERSION_MINOR=2
    YAML_VERSION_PATCH=5
    # hev-task-system configs (from configs.mk)
    CONFIG_STACK_BACKEND=STACK_MMAP
    CONFIG_STACK_OVERFLOW_DETECTION=1
    CONFIG_MEMALLOC_SLICE_ALIGN=16
    CONFIG_MEMALLOC_SLICE_MAX_SIZE=4096
    CONFIG_MEMALLOC_SLICE_MAX_COUNT=1000
    CONFIG_SCHED_CLOCK=CLOCK_NONE
    ENABLE_MEMALLOC_SLICE
    ENABLE_IO_SPLICE_SYSCALL
)

# ── Link libraries ──────────────────────────────────────────────────────

if(UNIX)
    target_link_libraries(hev-socks5-tunnel PRIVATE pthread)
    if(APPLE)
        # macOS may need additional frameworks
    endif()
elseif(WIN32)
    target_link_libraries(hev-socks5-tunnel PRIVATE ws2_32 iphlpapi)
endif()

# ── Compiler flags ──────────────────────────────────────────────────────

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(hev-socks5-tunnel PRIVATE -O3)
endif()

# Strip in Release
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND UNIX)
    set_target_properties(hev-socks5-tunnel PROPERTIES
        LINK_FLAGS_RELEASE "-s"
    )
endif()
