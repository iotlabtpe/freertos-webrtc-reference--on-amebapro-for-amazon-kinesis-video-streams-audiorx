cmake_minimum_required(VERSION 3.6.3)

# Apply patch for libraries/ambpro2_sdk repo.
set( AMB_SDK_DIRECTORY ${REPO_ROOT_DIRECTORY}/libraries/ambpro2_sdk )
execute_process(
     COMMAND bash -c "git apply --whitespace=nowarn --reject ${REPO_ROOT_DIRECTORY}/patch/lwipopts_enable_ipv6_and_loopback.patch"
     WORKING_DIRECTORY ${AMB_SDK_DIRECTORY}
)
