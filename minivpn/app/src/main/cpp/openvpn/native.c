#ifdef TARGET_ANDROID

#include <jni.h>

jstring
Java_world_daochen_minivpn_Native_stringFromJNI(JNIEnv *env, jclass jc) {
    return (*env)->NewStringUTF(env, TARGET_ABI);
}

jstring
Java_world_daochen_minivpn_Native_getAbi(JNIEnv *env, jclass jc){
    return (*env)->NewStringUTF(env, TARGET_ABI);
}

jstring
Java_de_blinkt_openvpn_core_NativeUtils_getJNIAPI(JNIEnv *env, jclass jo){
    return (*env)->NewStringUTF(env, TARGET_ABI);
}

#endif