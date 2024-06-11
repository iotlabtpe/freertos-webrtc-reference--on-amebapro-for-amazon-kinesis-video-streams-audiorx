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

file(
  GLOB
  WEBRTC_APPLICATION_MASTER_SOURCE_FILES
  "${REPO_ROOT_DIRECTORY}/examples/master/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/signaling_controller/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/network_transport/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/network_transport/tcp_sockets_wrapper/ports/lwip/*.c"
  "${REPO_ROOT_DIRECTORY}/examples/networking/corehttp_helper/*.c" )

set( WEBRTC_APPLICATION_MASTER_INCLUDE_DIRS
     "${REPO_ROOT_DIRECTORY}/examples/master/"
     "${REPO_ROOT_DIRECTORY}/examples/signaling_controller"
     "${REPO_ROOT_DIRECTORY}/examples/network_transport"
     "${REPO_ROOT_DIRECTORY}/examples/network_transport/tcp_sockets_wrapper/include"
     "${REPO_ROOT_DIRECTORY}/examples/networking"
     "${REPO_ROOT_DIRECTORY}/examples/networking/corehttp_helper"
     "${REPO_ROOT_DIRECTORY}/examples/logging"
     "${REPO_ROOT_DIRECTORY}/examples/sigv4" )

# Include dependencies
# Include coreHTTP
include( ${REPO_ROOT_DIRECTORY}/libraries/coreHTTP/httpFilePaths.cmake )

# Include sigV4
include( ${REPO_ROOT_DIRECTORY}/libraries/crypto/SigV4-for-AWS-IoT-embedded-sdk/sigv4FilePaths.cmake )

## Include coreJSON
include( ${REPO_ROOT_DIRECTORY}/libraries/coreJSON/jsonFilePaths.cmake )

# Include signaling
include( ${REPO_ROOT_DIRECTORY}/libraries/components/amazon-kinesis-video-streams-signaling/signalingFilePaths.cmake )

## Include SDP
# include( ${REPO_ROOT_DIRECTORY}/CMake/sdp.cmake )

## Include STUN
# include( ${REPO_ROOT_DIRECTORY}/CMake/stun.cmake )

## Set STUN include directories
# target_include_directories( WebRTCLinuxApplicationMaster PRIVATE
#                             ${STUN_INCLUDE_PUBLIC_DIRS} )

## Include ICE
# include( ${REPO_ROOT_DIRECTORY}/CMake/ice.cmake )

## Set ICE include directories
# target_include_directories( WebRTCLinuxApplicationMaster PRIVATE
#                             ${ICE_INCLUDE_PUBLIC_DIRS} )

# link application with dependencies, note that rt is librt providing message queue's APIs
# message(STATUS "linking websockets to WebRTCLinuxApplication")
# target_link_libraries(WebRTCLinuxApplicationMaster websockets sigv4 signaling corejson sdp ice rt pthread)

list(
	APPEND app_flags
     SIGNALING_DO_NOT_USE_CUSTOM_CONFIG
     SIGV4_DO_NOT_USE_CUSTOM_CONFIG
)

set( webrtc_master_demo_src
     ${WEBRTC_APPLICATION_MASTER_SOURCE_FILES}
     ${HTTP_SOURCES}
     ${SIGV4_SOURCES}
     ${SIGNALING_SOURCES}
     ${JSON_SOURCES} )
    #  ${WEBRTC_APPLICATION_SIGNALING_CONTROLLER_SOURCE_FILES}
    #  ${WEBRTC_APPLICATION_NETWORKING_LIBWEBSOCKETS_SOURCE_FILES}
    #  ${WEBRTC_APPLICATION_UTILS_SOURCE_FILES}
    #  ${WEBRTC_APPLICATION_SDP_CONTROLLER_SOURCE_FILES}
    #  ${WEBRTC_APPLICATION_ICE_CONTROLLER_SOURCE_FILES} )

set( webrtc_master_demo_include
     ${WEBRTC_APPLICATION_MASTER_INCLUDE_DIRS}
     ${HTTP_INCLUDE_PUBLIC_DIRS}
     ${SIGV4_INCLUDE_PUBLIC_DIRS}
     ${SIGNALING_INCLUDE_PUBLIC_DIRS}
     ${JSON_INCLUDE_PUBLIC_DIRS} )
    #  ${WEBRTC_APPLICATION_NETWORKING_LIBWEBSOCKETS_INCLUDE_DIRS}
    #  ${WEBRTC_APPLICATION_SIGNALING_CONTROLLER_INCLUDE_DIRS}
    #  ${WEBRTC_APPLICATION_UTILS_INCLUDE_DIRS}
    #  ${WEBRTC_APPLICATION_SDP_CONTROLLER_INCLUDE_DIRS}
    #  ${WEBRTC_APPLICATION_ICE_CONTROLLER_INCLUDE_DIRS}
    #  ${SIGV4_INCLUDE_PUBLIC_DIRS}
    #  ${LIBWEBSOCKETS_INCLUDE_DIRS}
    #  ${JSON_INCLUDE_PUBLIC_DIRS}
    #  ${SIGNALING_INCLUDE_PUBLIC_DIRS}
    #  ${SDP_INCLUDE_PUBLIC_DIRS} )
