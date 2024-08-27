cmake_minimum_required(VERSION 3.6.3)

project(FreeRTOSWebRTCMasterApplication VERSION 0.0.1 LANGUAGES C)

set(REPO_ROOT_DIRECTORY ${repo_root})

# file(
#   GLOB
#   WEBRTC_APPLICATION_SIGNALING_CONTROLLER_SOURCE_FILES
#   "${REPO_ROOT_DIRECTORY}/examples/signaling_controller/*.c" )

# set( WEBRTC_APPLICATION_SIGNALING_CONTROLLER_INCLUDE_DIRS
#      "${REPO_ROOT_DIRECTORY}/examples/signaling_controller/" )

# file(
#   GLOB
#   WEBRTC_APPLICATION_NETWORKING_LIBWEBSOCKETS_SOURCE_FILES
#   "${REPO_ROOT_DIRECTORY}/examples/networking/networkingLibwebsockets/*.c" )

# set( WEBRTC_APPLICATION_NETWORKING_LIBWEBSOCKETS_INCLUDE_DIRS
#      "${REPO_ROOT_DIRECTORY}/examples/networking/"
#      "${REPO_ROOT_DIRECTORY}/examples/networking/networkingLibwebsockets/" )

# file(
#   GLOB
#   WEBRTC_APPLICATION_UTILS_SOURCE_FILES
#   "${REPO_ROOT_DIRECTORY}/examples/base64/*.c"
#   "${REPO_ROOT_DIRECTORY}/examples/logging/*.c"
#   "${REPO_ROOT_DIRECTORY}/examples/message_queue/linux/*.c"
#   "${REPO_ROOT_DIRECTORY}/examples/timer_controller/*.c"
#   "${REPO_ROOT_DIRECTORY}/examples/string_utils/*.c" )

# set( WEBRTC_APPLICATION_UTILS_INCLUDE_DIRS
#      "${REPO_ROOT_DIRECTORY}/examples/base64/"
#      "${REPO_ROOT_DIRECTORY}/examples/logging/"
#      "${REPO_ROOT_DIRECTORY}/examples/message_queue/linux/"
#      "${REPO_ROOT_DIRECTORY}/examples/timer_controller/"
#      "${REPO_ROOT_DIRECTORY}/examples/string_utils" )

# file(
#   GLOB
#   WEBRTC_APPLICATION_SDP_CONTROLLER_SOURCE_FILES
#   "${REPO_ROOT_DIRECTORY}/examples/sdp_controller/*.c" )

# set( WEBRTC_APPLICATION_SDP_CONTROLLER_INCLUDE_DIRS
#      "${REPO_ROOT_DIRECTORY}/examples/sdp_controller/" )

# file(
#   GLOB
#   WEBRTC_APPLICATION_ICE_CONTROLLER_SOURCE_FILES
#   "${REPO_ROOT_DIRECTORY}/examples/ice_controller/*.c" )

# set( WEBRTC_APPLICATION_ICE_CONTROLLER_INCLUDE_DIRS
#     "examples/ice_controller/" )

# file(
#   GLOB
#   WEBRTC_APPLICATION_MASTER_SOURCE_FILES
#   "${REPO_ROOT_DIRECTORY}/examples/master/*.c" )

# set( WEBRTC_APPLICATION_MASTER_INCLUDE_DIRS
#      "${REPO_ROOT_DIRECTORY}/examples/master/" )

include( ${REPO_ROOT_DIRECTORY}/patch/apply_patches.cmake )

file(
  GLOB
  WEBRTC_APPLICATION_MASTER_SOURCE_FILES
  "${REPO_ROOT_DIRECTORY}/examples/master/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/peer_connection/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/signaling_controller/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/network_transport/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/network_transport/tcp_sockets_wrapper/ports/lwip/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/network_transport/udp_sockets_wrapper/ports/lwip/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/networking/corehttp_helper/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/networking/networking_utils/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/networking/wslay_helper/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/message_queue/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/base64/mbedtls/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/sdp_controller/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/string_utils/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/ice_controller/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/timer_controller/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/app_media_source/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/app_media_source/port/ameba_pro2/*.c" )

set( WEBRTC_APPLICATION_MASTER_INCLUDE_DIRS
     "${REPO_ROOT_DIRECTORY}/examples/master/"
     "${REPO_ROOT_DIRECTORY}/examples/peer_connection/"
     "${REPO_ROOT_DIRECTORY}/examples/signaling_controller"
     "${REPO_ROOT_DIRECTORY}/examples/network_transport"
     "${REPO_ROOT_DIRECTORY}/examples/network_transport/tcp_sockets_wrapper/include"
     "${REPO_ROOT_DIRECTORY}/examples/network_transport/udp_sockets_wrapper/include"
     "${REPO_ROOT_DIRECTORY}/examples/networking"
     "${REPO_ROOT_DIRECTORY}/examples/networking/corehttp_helper"
     "${REPO_ROOT_DIRECTORY}/examples/networking/wslay_helper"
     "${REPO_ROOT_DIRECTORY}/examples/networking/networking_utils"
     "${REPO_ROOT_DIRECTORY}/examples/logging"
     "${REPO_ROOT_DIRECTORY}/examples/sigv4"
     "${REPO_ROOT_DIRECTORY}/examples/message_queue"
     "${REPO_ROOT_DIRECTORY}/examples/base64"
     "${REPO_ROOT_DIRECTORY}/examples/sdp_controller"
     "${REPO_ROOT_DIRECTORY}/examples/string_utils"
     "${REPO_ROOT_DIRECTORY}/examples/ice_controller"
     "${REPO_ROOT_DIRECTORY}/examples/timer_controller"
     "${REPO_ROOT_DIRECTORY}/examples/app_media_source"
     "${REPO_ROOT_DIRECTORY}/examples/app_media_source/port/ameba_pro2" )

# Include dependencies
# Include coreHTTP
include( ${REPO_ROOT_DIRECTORY}/libraries/coreHTTP/httpFilePaths.cmake )

# Include sigV4
include( ${REPO_ROOT_DIRECTORY}/libraries/crypto/SigV4-for-AWS-IoT-embedded-sdk/sigv4FilePaths.cmake )

## Include coreJSON
include( ${REPO_ROOT_DIRECTORY}/libraries/coreJSON/jsonFilePaths.cmake )

# Include signaling
include( ${REPO_ROOT_DIRECTORY}/libraries/components/amazon-kinesis-video-streams-signaling/signalingFilePaths.cmake )

# Include wslay
file(
  GLOB
  WSLAY_SOURCE_FILES
  "${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/*.c" )

configure_file(${REPO_ROOT_DIRECTORY}/CMake/wslay/wslay_net.h.in
               ${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/wslay_net.h @ONLY)

configure_file(${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/includes/wslay/wslayver.h.in
               ${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/includes/wslay/wslayver.h @ONLY)
set( WSLAY_INCLUDE_DIRS
     "${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/"
     "${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/includes"
     "${REPO_ROOT_DIRECTORY}/libraries/wslay/lib/includes/wslay" )

# Include SDP
include( ${REPO_ROOT_DIRECTORY}/libraries/components/amazon-kinesis-video-streams-sdp/sdpFilePaths.cmake )

# Include STUN
include( ${REPO_ROOT_DIRECTORY}/libraries/components/amazon-kinesis-video-streams-stun/stunFilePaths.cmake )

# Include RTP
include( ${REPO_ROOT_DIRECTORY}/libraries/components/amazon-kinesis-video-streams-rtp/rtpFilePaths.cmake )

# Include RTP
include( ${REPO_ROOT_DIRECTORY}/libraries/components/amazon-kinesis-video-streams-rtcp/rtcpFilePaths.cmake )

# Include ICE
include( ${REPO_ROOT_DIRECTORY}/CMake/ice.cmake )

# Include libsrtp
include( ${REPO_ROOT_DIRECTORY}/CMake/libsrtp.cmake )

list(
	APPEND app_flags
     SDP_DO_NOT_USE_CUSTOM_CONFIG
     SIGV4_DO_NOT_USE_CUSTOM_CONFIG
)

set( webrtc_master_demo_src
     ${WEBRTC_APPLICATION_MASTER_SOURCE_FILES}
     ${HTTP_SOURCES}
     ${SIGV4_SOURCES}
     ${SIGNALING_SOURCES}
     ${JSON_SOURCES}
     ${WSLAY_SOURCE_FILES}
     ${SDP_SOURCES}
     ${STUN_SOURCES}
     ${ICE_SOURCES}
     ${RTP_SOURCES}
     ${RTCP_SOURCES} )

set( webrtc_master_demo_include
     ${WEBRTC_APPLICATION_MASTER_INCLUDE_DIRS}
     ${HTTP_INCLUDE_PUBLIC_DIRS}
     ${SIGV4_INCLUDE_PUBLIC_DIRS}
     ${SIGNALING_INCLUDE_PUBLIC_DIRS}
     ${JSON_INCLUDE_PUBLIC_DIRS}
     ${WSLAY_INCLUDE_DIRS}
     ${SDP_INCLUDE_PUBLIC_DIRS}
     ${STUN_INCLUDE_PUBLIC_DIRS}
     ${ICE_INCLUDE_PUBLIC_DIRS}
     ${RTP_INCLUDE_PUBLIC_DIRS}
     ${RTCP_INCLUDE_PUBLIC_DIRS} )

# Set more strict rules to application code only
set_source_files_properties(
     ${WEBRTC_APPLICATION_MASTER_SOURCE_FILES}
     ${WEBRTC_APPLICATION_MASTER_INCLUDE_DIRS}
     PROPERTIES
     COMPILE_FLAGS "-Werror"
)
