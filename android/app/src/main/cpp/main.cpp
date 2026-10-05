#include <jni.h>
#include <android/binder_ibinder.h>
#include <android/binder_ibinder_jni.h>
#include <dlfcn.h>

#include "checker/logging.h"

void checker_run(JNIEnv *env, jobject context, jobject callback);
jstring checker_collect_cloud_device_evidence(JNIEnv *env);
jstring checker_create_cloud_attestation(
        JNIEnv *env, jobject context, jbyteArray challenge, jbyteArray payload_digest);
jbyteArray checker_cloud_sha256(JNIEnv *env, jbyteArray payload);
jboolean checker_verify_cloud_verdict(
        JNIEnv *env, jbyteArray payload, jbyteArray signature, jbyteArray public_key);
JNIEXPORT jint JNICALL TrustAttestorZygotePreload_check(JNIEnv *env, jobject thiz);
JNIEXPORT jint JNICALL TrustAttestorReadProcProbe_check(JNIEnv *env, jobject thiz);

static void native_run(JNIEnv *env, jobject thiz, jobject context, jobject callback) {
    (void)thiz;
    checker_run(env, context, callback);
}

static jstring native_collect_cloud_device_evidence(JNIEnv *env, jobject) {
    return checker_collect_cloud_device_evidence(env);
}

static jstring native_create_cloud_attestation(
        JNIEnv *env,
        jobject,
        jobject context,
        jbyteArray challenge,
        jbyteArray payload_digest) {
    return checker_create_cloud_attestation(env, context, challenge, payload_digest);
}

static jbyteArray native_cloud_sha256(JNIEnv *env, jobject, jbyteArray payload) {
    return checker_cloud_sha256(env, payload);
}

static jboolean native_verify_cloud_verdict(
        JNIEnv *env,
        jobject,
        jbyteArray payload,
        jbyteArray signature,
        jbyteArray public_key) {
    return checker_verify_cloud_verdict(env, payload, signature, public_key);
}

static jint native_check(JNIEnv *env, jobject thiz) {
    return TrustAttestorZygotePreload_check(env, thiz);
}

static jint native_read_proc_check(JNIEnv *env, jobject thiz) {
    return TrustAttestorReadProcProbe_check(env, thiz);
}

namespace {

// Keep the NDK Binder dependency dynamically resolved. TrustAttestor still
// supports API 27, while AIBinder_fromJavaBinder/isRemote/getUserData were
// introduced in API 29. The DEX probe already gates itself to API 31, but a
// missing symbol must remain a normal unavailable result rather than preventing
// the native library from loading on older releases.
constexpr jlong kBinderAttributesAvailable = 1LL << 0;
constexpr jlong kBinderAttributesRemote = 1LL << 1;
constexpr jlong kBinderAttributesUserData = 1LL << 2;
constexpr jlong kBinderAttributesClass = 1LL << 3;
constexpr jlong kBinderAttributesUnavailable = -1;

using BinderFromJavaFn = AIBinder *(*)(JNIEnv *, jobject);
using BinderIsRemoteFn = bool (*)(const AIBinder *);
using BinderGetUserDataFn = void *(*)(AIBinder *);
using BinderGetClassFn = const AIBinder_Class *(*)(AIBinder *);
using BinderDecStrongFn = void (*)(AIBinder *);

struct BinderApi {
    void *handle = nullptr;
    BinderFromJavaFn fromJava = nullptr;
    BinderIsRemoteFn isRemote = nullptr;
    BinderGetUserDataFn getUserData = nullptr;
    BinderGetClassFn getClass = nullptr;
    BinderDecStrongFn decStrong = nullptr;

    bool ready() const {
        return handle != nullptr && fromJava != nullptr && isRemote != nullptr
                && getUserData != nullptr && getClass != nullptr && decStrong != nullptr;
    }
};

template <typename T>
T binderSymbol(void *handle, const char *name) {
    return handle == nullptr
            ? nullptr
            : reinterpret_cast<T>(dlsym(handle, name));
}

const BinderApi &binderApi() {
    static const BinderApi api = [] {
        BinderApi value;
        value.handle = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_LOCAL);
        if (value.handle == nullptr) return value;
        value.fromJava = binderSymbol<BinderFromJavaFn>(
                value.handle, "AIBinder_fromJavaBinder");
        value.isRemote = binderSymbol<BinderIsRemoteFn>(
                value.handle, "AIBinder_isRemote");
        value.getUserData = binderSymbol<BinderGetUserDataFn>(
                value.handle, "AIBinder_getUserData");
        value.getClass = binderSymbol<BinderGetClassFn>(
                value.handle, "AIBinder_getClass");
        value.decStrong = binderSymbol<BinderDecStrongFn>(
                value.handle, "AIBinder_decStrong");
        return value;
    }();
    return api;
}

jlong native_binder_attributes(JNIEnv *env, jobject, jobject java_binder) {
    if (java_binder == nullptr) return kBinderAttributesUnavailable;
    const BinderApi &api = binderApi();
    if (!api.ready()) return kBinderAttributesUnavailable;

    AIBinder *binder = api.fromJava(env, java_binder);
    if (binder == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return kBinderAttributesUnavailable;
    }

    jlong result = kBinderAttributesAvailable;
    if (api.isRemote(binder)) result |= kBinderAttributesRemote;
    if (api.getUserData(binder) != nullptr) result |= kBinderAttributesUserData;
    if (api.getClass(binder) != nullptr) result |= kBinderAttributesClass;
    api.decStrong(binder);
    return result;
}

}  // namespace

static int get_sdk_int(JNIEnv *env) {
    jclass version_class = env->FindClass("android/os/Build$VERSION");
    if (version_class == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return 0;
    }
    jfieldID sdk_field = env->GetStaticFieldID(version_class, "SDK_INT", "I");
    if (sdk_field == nullptr) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(version_class);
        return 0;
    }
    int sdk = env->GetStaticIntField(version_class, sdk_field);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        sdk = 0;
    }
    env->DeleteLocalRef(version_class);
    return sdk;
}

/*
extern "C" JNIEXPORT void JNICALL Java_com_lingqing_trustattestor_TrustAttestorNativeBridge_run(JNIEnv *env, jclass, jobject context, jobject callback) {
    checker_run(env, context, callback);
}
*/

static JNINativeMethod gMethods[] = {
        {
                const_cast<char *>("nativeRun"),
                const_cast<char *>("(Landroid/content/Context;Lcom/lingqing/trustattestor/NativeScanCallback;)V"),
                reinterpret_cast<void *>(native_run)
        },
        {
                const_cast<char *>("nativeCollectCloudDeviceEvidence"),
                const_cast<char *>("()Ljava/lang/String;"),
                reinterpret_cast<void *>(native_collect_cloud_device_evidence)
        },
        {
                const_cast<char *>("nativeCreateCloudAttestation"),
                const_cast<char *>("(Landroid/content/Context;[B[B)Ljava/lang/String;"),
                reinterpret_cast<void *>(native_create_cloud_attestation)
        },
        {
                const_cast<char *>("nativeSha256"),
                const_cast<char *>("([B)[B"),
                reinterpret_cast<void *>(native_cloud_sha256)
        },
        {
                const_cast<char *>("nativeVerifyCloudVerdict"),
                const_cast<char *>("([B[B[B)Z"),
                reinterpret_cast<void *>(native_verify_cloud_verdict)
        },
        {
                const_cast<char *>("nativeBinderAttributes"),
                const_cast<char *>("(Landroid/os/IBinder;)J"),
                reinterpret_cast<void *>(native_binder_attributes)
        }
};

static JNINativeMethod gZygotePreloadMethods[] = {
        {
                const_cast<char *>("check"),
                const_cast<char *>("()I"),
                reinterpret_cast<void *>(native_check)
        },
};

static JNINativeMethod gReadProcProbeMethods[] = {
        {
                const_cast<char *>("check"),
                const_cast<char *>("()I"),
                reinterpret_cast<void *>(native_read_proc_check)
        }
};

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }

    // Hidden-API exemption is an optimization for the wider checker, not a
    // prerequisite for loading the native bridge. Older Android releases and
    // some vendor runtimes legitimately do not expose this method.
    LOGD("trying bypass hiddenapi");
    auto clazz = env->FindClass("dalvik/system/VMRuntime");
    if (clazz == nullptr) {
        env->ExceptionClear();
        LOGE("hiddenapi: VMRuntime not found");
    } else {
        auto getRuntime = env->GetStaticMethodID(clazz, "getRuntime", "()Ldalvik/system/VMRuntime;");
        if (getRuntime == nullptr) {
            env->ExceptionClear();
            LOGE("hiddenapi: getRuntime not found");
        } else {
            auto method = env->GetMethodID(
                    clazz, "setHiddenApiExemptions", "([Ljava/lang/String;)V");
            if (method == nullptr) {
                env->ExceptionClear();
                LOGE("hiddenapi: setHiddenApiExemptions not found");
            } else {
                auto stringClass = env->FindClass("java/lang/String");
                auto str = stringClass == nullptr ? nullptr : env->NewStringUTF("");
                auto arr = (stringClass == nullptr || str == nullptr)
                        ? nullptr : env->NewObjectArray(1, stringClass, str);
                jobject runtime = nullptr;
                if (!env->ExceptionCheck()) {
                    runtime = env->CallStaticObjectMethod(clazz, getRuntime);
                    if (arr != nullptr && runtime != nullptr && !env->ExceptionCheck()) {
                        env->CallVoidMethod(runtime, method, arr);
                    }
                }
                if (env->ExceptionCheck()) env->ExceptionClear();
                if (runtime != nullptr) env->DeleteLocalRef(runtime);
                if (arr != nullptr) env->DeleteLocalRef(arr);
                if (str != nullptr) env->DeleteLocalRef(str);
                if (stringClass != nullptr) env->DeleteLocalRef(stringClass);
            }
        }
        env->DeleteLocalRef(clazz);
    }

    jclass nb_clazz = env->FindClass("com/lingqing/trustattestor/TrustAttestorNativeBridge");
    if (nb_clazz == nullptr) {
        return JNI_ERR;
    }

    if (env->RegisterNatives(nb_clazz, gMethods, sizeof(gMethods) / sizeof(gMethods[0])) != JNI_OK) {
        env->DeleteLocalRef(nb_clazz);
        return JNI_ERR;
    }

    env->DeleteLocalRef(nb_clazz);

    // android.app.ZygotePreload was added in API 29. Resolving its implementing
    // class on API 27/28 can fail during class verification, so skip this
    // registration entirely on those releases.
    if (get_sdk_int(env) >= 29) {
        jclass zygote_preload_clazz = env->FindClass(
                "com/lingqing/trustattestor/TrustAttestorZygotePreload");
        if (zygote_preload_clazz == nullptr) {
            return JNI_ERR;
        }

        if (env->RegisterNatives(
                zygote_preload_clazz,
                gZygotePreloadMethods,
                sizeof(gZygotePreloadMethods) / sizeof(gZygotePreloadMethods[0])) != JNI_OK) {
            env->DeleteLocalRef(zygote_preload_clazz);
            return JNI_ERR;
        }

        env->DeleteLocalRef(zygote_preload_clazz);

        jclass read_proc_clazz = env->FindClass(
                "com/lingqing/trustattestor/ReadProcProbeService");
        if (read_proc_clazz == nullptr) {
            return JNI_ERR;
        }

        if (env->RegisterNatives(
                read_proc_clazz,
                gReadProcProbeMethods,
                sizeof(gReadProcProbeMethods) / sizeof(gReadProcProbeMethods[0])) != JNI_OK) {
            env->DeleteLocalRef(read_proc_clazz);
            return JNI_ERR;
        }

        env->DeleteLocalRef(read_proc_clazz);
    }
    return JNI_VERSION_1_6;
}
