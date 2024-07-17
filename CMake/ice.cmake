# ICE library source files.
set( ICE_SOURCES
     "${CMAKE_CURRENT_LIST_DIR}/../libraries/components/amazon-kinesis-video-streams-ice/source/ice_api.c"
     "${CMAKE_CURRENT_LIST_DIR}/../libraries/components/amazon-kinesis-video-streams-ice/source/ice_api_private.c"
     "${CMAKE_CURRENT_LIST_DIR}/../libraries/components/amazon-kinesis-video-streams-ice/source/transaction_id_store.c" )

# ICE library Public Include directories.
set( ICE_INCLUDE_PUBLIC_DIRS
     "${CMAKE_CURRENT_LIST_DIR}/../libraries/components/amazon-kinesis-video-streams-ice/source/include" )