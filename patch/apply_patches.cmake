cmake_minimum_required(VERSION 3.6.3)

# Apply patch for libraries/ambpro2_sdk repo.
set( AMB_SDK_DIRECTORY ${REPO_ROOT_DIRECTORY}/libraries/ambpro2_sdk )
execute_process(
     COMMAND bash -c "git apply --whitespace=nowarn --reject ${REPO_ROOT_DIRECTORY}/patch/lwipopts_enable_ipv6_and_loopback_and_sntp_recv_timeout.patch"
     WORKING_DIRECTORY ${AMB_SDK_DIRECTORY}
)

execute_process(
     COMMAND bash -c "git apply --whitespace=nowarn --reject ${REPO_ROOT_DIRECTORY}/patch/mbedtls_config.patch"
     WORKING_DIRECTORY ${AMB_SDK_DIRECTORY}
)

execute_process(
     COMMAND bash -c "git apply --whitespace=nowarn --reject ${REPO_ROOT_DIRECTORY}/patch/rtw_opt_skbuf_rtl8735b_enlarge_skb_buffer_number.patch"
     WORKING_DIRECTORY ${AMB_SDK_DIRECTORY}
)

execute_process(
     COMMAND bash -c "git apply --whitespace=nowarn --reject ${REPO_ROOT_DIRECTORY}/patch/fwfs_local_label.patch"
     WORKING_DIRECTORY ${AMB_SDK_DIRECTORY}
)

set( WSLAY_DIRECTORY ${REPO_ROOT_DIRECTORY}/libraries/wslay )
execute_process(
     COMMAND bash -c "git apply --whitespace=nowarn --reject ${REPO_ROOT_DIRECTORY}/patch/wslay_net.patch"
     WORKING_DIRECTORY ${WSLAY_DIRECTORY}
)
