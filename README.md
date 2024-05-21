# FreeRTOS-WebRTC

## Prerequisite
### Toolchain
```
cd libraries/ambpro2_sdk/tools
cat asdk-10.3.0-linux-newlib-build-3633-x86_64.tar.bz2.* | tar jxvf -
export PATH=libraries/ambpro2_sdk/tools/asdk-10.3.0/linux/newlib/bin:$PATH
```

## Build project
1. Open linux terminal and enter the project location: project/realtek_amebapro2_webrtc_application/GCC-RELEASE.
1. Create folder “build” and enter “build” folder.
1. Run “cmake .. -G"Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=../toolchain.cmake” to create the makefile.
1. Run “cmake --build . --target flash” to build and generate flash binary.

<!-- TODO: Flash tool can be downloaded in Amazon only. -->
## Flash image
1. Download the [Flash Tool](https://quip-amazon.com/-/blob/QCb9AAoSj4u/mq-Ip0mBd-SnIxv1FFVefQ?name=Pro2_PG_tool%20_v1.3.2_temp1.zip) from Amazon Quip.
1. Copy compiled image `flash_ntz.bin` to Pro2_PG_tool _v1.3.2_temp1 folder together with uartfwburn.exe
2. Make sure the jumper of J27 is plugged to enter download mode.
3. Plug the device to host.
4. Open terminal and goto Pro2_PG_tool _v1.3.2_temp1 directory.
    1. cd Pro2_PG_tool _v1.3.2_temp1 
    1. If NAND flash (Ameba Pro2)
        1. uartfwburn.exe -p COMxx -f flash_ntz.bin -b 3000000 -n pro2
    1. If NOR flash (Ameba Pro2 Mini)
        1. uartfwburn.exe -p COMxx -f flash_ntz.bin -b 3000000
    1. If using Ameba Pro2 Mini, the maximum baudrate is 2000000. Besides that, we can use -U to speed up the flash time because Ameba Pro2 Mini is NOR flash.
        1. uartfwburn.exe -p COMxx -f flash_ntz.bin -b 2000000 -U


## Trouble shooting

1. Permission denied of accessing project/realtek_amebapro2_webrtc_application/GCC-RELEASE/mp/*.linux
    1. Provide execute permission to current user.
    1. Or use command chmod to add execute permission, for example: `chmod +x project/realtek_amebapro2_webrtc_application/GCC-RELEASE/mp/*.linux`

