add_executable(libovpnexec.so minivpn/minivpn.c)
target_compile_options(libovpnexec.so PRIVATE -fPIE)
target_link_libraries(libovpnexec.so PRIVATE openvpn -fPIE -pie)

add_executable(pie_openvpn.${ANDROID_ABI} minivpn/minivpn.c)
target_compile_options(pie_openvpn.${ANDROID_ABI} PRIVATE -fPIE)
target_link_libraries(pie_openvpn.${ANDROID_ABI} PRIVATE openvpn -fPIE -pie)