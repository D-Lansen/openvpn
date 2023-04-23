#include <jni.h>

JNIEXPORT jstring JNICALL
Java_world_daochen_minivpn_Native_stringFromJNI(JNIEnv *env, jclass jc) {
    return (*env)->NewStringUTF(env, "test_print");
}

JNIEXPORT jstring JNICALL
Java_world_daochen_minivpn_Native_getAbi(JNIEnv *env, jclass jc){
    return (*env)->NewStringUTF(env, TARGET_ABI);
}
