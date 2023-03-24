#include <jni.h>

jstring Java_de_blinkt_openvpn_core_NativeUtils_getJNIAPI(JNIEnv *env, jclass jo){
    return (*env)->NewStringUTF(env, TARGET_ARCH_ABI);
}