cmake_minimum_required(VERSION 3.6)

project(usrsctp)

set(usrsctp usrsctp)

list(
    APPEND usrsctp_sources

###netinet
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_asconf.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_auth.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_bsd_addr.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_callout.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_cc_functions.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_crc32.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_indata.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_input.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_output.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_pcb.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_peeloff.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_sha1.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_ss_functions.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_sysctl.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_timer.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_userspace.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctp_usrreq.c
	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet/sctputil.c
###netinet6
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet6/sctp6_usrreq.c

    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/user_environment.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/user_mbuf.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/user_recv_thread.c
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/user_socket.c
)

add_library(
    ${usrsctp} STATIC
    ${usrsctp_sources}
)

list(
	APPEND usrsctp_flags
	CONFIG_BUILD_RAM=1 
	CONFIG_BUILD_LIB=1 
	CONFIG_PLATFORM_8735B
	CONFIG_RTL8735B_PLATFORM=1
	CONFIG_SYSTEM_TIME64=1
    
    __Userspace__
    SCTP_SIMPLE_ALLOCATOR
    SCTP_PROCESS_LEVEL_LOCKS
    SCTP_USE_MBEDTLS_SHA1
    SCTP_USE_LWIP
    SCTP_USE_RTOS
    SCTP_DEBUG
    INET
    # INET6
    
    # HAVE_STDATOMIC_H
    HAVE_SA_LEN
    HAVE_SIN_LEN
    # HAVE_SIN6_LEN
    HAVE_SCONN_LEN

    KVS_PLAT_RTK_FREERTOS
)

target_compile_definitions(${usrsctp} PUBLIC ${usrsctp_flags} )

include( ${CMAKE_CURRENT_LIST_DIR}/../project/realtek_amebapro2_webrtc_application/GCC-RELEASE/includepath.cmake )

target_include_directories(
	${usrsctp}
	PUBLIC

    ${inc_path}
	${sdk_root}/component/os/freertos/${freertos}/Source/portable/GCC/ARM_CM33_NTZ/non_secure

	${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet
    ${CMAKE_CURRENT_LIST_DIR}/../libraries/usrsctp/usrsctplib/netinet6
)

target_include_directories(
	${usrsctp}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../project/realtek_amebapro2_webrtc_application/src/amazon_kvs/lib_amazon/gcc_include
)

### add linked library ###
list(
    APPEND app_example_lib
    usrsctp
)

