#include <jni.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(__ANDROID__)
#include <android/log.h>
#define PCLI_JNI_TAG "pcli-jni"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, PCLI_JNI_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, PCLI_JNI_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, PCLI_JNI_TAG, __VA_ARGS__)
#else
#define LOGI(...) do { std::fprintf(stderr, "[I/pcli-jni] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
#define LOGW(...) do { std::fprintf(stderr, "[W/pcli-jni] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
#define LOGE(...) do { std::fprintf(stderr, "[E/pcli-jni] " __VA_ARGS__); std::fprintf(stderr, "\n"); } while (0)
#endif

#if !defined(PCLI_ANDROID_STUB)
#include "pcli/log.hpp"
#include "pcli/route/table.hpp"
#include "pcli/stack/api_hub.hpp"
#include "pcli/stack/hot_converge.hpp"
#include "pcli/stack/mixed_inbound.hpp"
#include "pcli/stack/stop.hpp"
#include "pcli/stack/urltest.hpp"
#include "pcli/version.hpp"
#if defined(PCLI_HAS_HYSTERIA2)
#include "pcli/net/hy2.hpp"
#endif
#if defined(PCLI_HAS_HY2MESH)
#include "pcli/net/hy2m.hpp"
#endif
#if defined(PCLI_HAS_TUIC)
#include "pcli/net/tuic.hpp"
#endif
#if defined(PCLI_HAS_XHTTP)
#include "pcli/stack/xhttp_pool.hpp"
#endif
#endif

namespace {

JavaVM* g_vm = nullptr;
jclass g_bridge_class = nullptr;
jmethodID g_log_method = nullptr;
pthread_key_t g_jni_detach_key;
std::atomic<bool> g_detach_key_ready(false);
std::atomic<bool> g_running(false);

void DetachThreadDestructor(void* ptr) {
  auto* vm = static_cast<JavaVM*>(ptr);
  if (vm != nullptr) {
    vm->DetachCurrentThread();
  }
}

JNIEnv* GetOrAttachEnv() {
  JavaVM* vm = g_vm;
  if (vm == nullptr) {
    return nullptr;
  }
  JNIEnv* env = nullptr;
  const jint rc = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
  if (rc == JNI_OK) {
    return env;
  }
  if (rc != JNI_EDETACHED) {
    return nullptr;
  }
#if defined(__ANDROID__)
  if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || env == nullptr) {
    return nullptr;
  }
#else
  if (vm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) != JNI_OK || env == nullptr) {
    return nullptr;
  }
#endif
  if (g_detach_key_ready.load(std::memory_order_acquire)) {
    ::pthread_setspecific(g_jni_detach_key, vm);
  }
  return env;
}

#if !defined(PCLI_ANDROID_STUB) && defined(__ANDROID__)
void NativeLogSink(pcli::log::Level level, const std::string& message) {
  const int priority = level == pcli::log::kError ? ANDROID_LOG_ERROR :
      level == pcli::log::kWarn ? ANDROID_LOG_WARN :
      level == pcli::log::kDebug ? ANDROID_LOG_DEBUG : ANDROID_LOG_INFO;
  __android_log_print(priority, "pcli", "%s", message.c_str());
  JNIEnv* env = GetOrAttachEnv();
  if (!env || !g_bridge_class || !g_log_method) return;
  jstring text = env->NewStringUTF(message.c_str());
  if (text) {
    env->CallStaticVoidMethod(g_bridge_class, g_log_method, static_cast<jint>(level), text);
    env->DeleteLocalRef(text);
  }
  if (env->ExceptionCheck()) env->ExceptionClear();
}
#endif

std::string JStringToStdString(JNIEnv* env, jstring value) {
  if (value == nullptr) {
    return std::string();
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (chars == nullptr) {
    return std::string();
  }
  std::string out(chars);
  env->ReleaseStringUTFChars(value, chars);
  return out;
}

struct RunGuard {
  ~RunGuard() {
    g_running.store(false, std::memory_order_release);
  }
};

#if !defined(PCLI_ANDROID_STUB)
int RunMixedEmbedded(const std::string& config_path) {
  pcli::route::Table table;
  if (!table.LoadFile(config_path) || !table.PrepareChains()) {
    LOGE("RunMixedEmbedded: failed to load or prepare config: %s", config_path.c_str());
    return -EINVAL;
  }

#if defined(PCLI_HAS_HYSTERIA2)
  pcli::hy2::Pool hy2;
#endif
#if defined(PCLI_HAS_HY2MESH)
  pcli::hy2m::Pool hy2m;
#endif
#if defined(PCLI_HAS_TUIC)
  pcli::tuic::Pool tuic;
#endif
#if defined(PCLI_HAS_XHTTP)
  pcli::stack::XhttpPool xhttp;
  pcli::stack::XhttpPool::SetCurrent(&xhttp);
#endif

  pcli::stack::MixedInbound mixed;
  if (!mixed.Open(&table) || !mixed.Active()) {
    LOGE("RunMixedEmbedded: failed to open mixed listener");
#if defined(PCLI_HAS_XHTTP)
    pcli::stack::XhttpPool::SetCurrent(nullptr);
#endif
    return -EADDRNOTAVAIL;
  }

#if defined(PCLI_HAS_HYSTERIA2)
  mixed.SetHy2Pool(&hy2);
#endif
#if defined(PCLI_HAS_HY2MESH)
  mixed.SetHy2mPool(&hy2m);
#endif
#if defined(PCLI_HAS_TUIC)
  mixed.SetTuicPool(&tuic);
#endif
  mixed.SetEgress("");

  pcli::stack::ApiHub& api = pcli::stack::ApiHub::Instance();
  {
    pcli::stack::ApiStackInfo info;
    info.stack = "mixed-android";
    info.mixed_port = table.MixedListenPort();
    info.mixed_host = table.MixedListenHost();
    info.dns = nullptr;
    api.Start(&table, info);
  }

  std::uint32_t cfg_epoch = table.ConfigEpoch();
  pcli::route::Table::SetRestartHook(&pcli::stack::RequestRestart);
  LOGI("RunMixedEmbedded: listening on %s:%d",
       table.MixedListenHost().c_str(), table.MixedListenPort());

  while (!pcli::stack::StopRequested()) {
    if (pcli::stack::ConsumeReload()) {
      table.StartHotReload(true);
    }
    if (pcli::stack::ConvergeConfig(&table, &cfg_epoch,
#if defined(PCLI_HAS_HYSTERIA2)
                                    &hy2,
#else
                                    nullptr,
#endif
#if defined(PCLI_HAS_TUIC)
                                    &tuic,
#else
                                    nullptr,
#endif
#if defined(PCLI_HAS_XHTTP)
                                    &xhttp)) {
#else
                                    nullptr)) {
#endif
      pcli::stack::StartUrltestProbes(&table);
    }

    std::vector<pollfd> pfds;
    mixed.FillPoll(&pfds);
#if defined(PCLI_HAS_HYSTERIA2)
    hy2.AppendPoll(&pfds);
#endif
#if defined(PCLI_HAS_HY2MESH)
    hy2m.AppendPoll(&pfds);
#endif
#if defined(PCLI_HAS_TUIC)
    tuic.AppendPoll(&pfds);
#endif
#if defined(PCLI_HAS_XHTTP)
    xhttp.AppendPoll(&pfds);
    const int xw = xhttp.WaitMs();
#endif
    api.FillPoll(&pfds);

    int w = mixed.WaitMs();
    api.ClampWait(&w);
#if defined(PCLI_HAS_HYSTERIA2)
    const int hw = hy2.WaitMs();
    if (hw >= 0 && (w < 0 || hw < w)) w = hw;
#endif
#if defined(PCLI_HAS_HY2MESH)
    const int hmw = hy2m.WaitMs();
    if (hmw >= 0 && (w < 0 || hmw < w)) w = hmw;
#endif
#if defined(PCLI_HAS_TUIC)
    const int tw = tuic.WaitMs();
    if (tw >= 0 && (w < 0 || tw < w)) w = tw;
#endif
#if defined(PCLI_HAS_XHTTP)
    if (xw >= 0 && (w < 0 || xw < w)) w = xw;
#endif

    const int timeout_ms = (w < 0 || w > 200) ? 200 : w;
    if (::poll(pfds.empty() ? nullptr : &pfds[0], pfds.size(), timeout_ms) < 0) {
      if (errno == EINTR) continue;
      continue;
    }

#if defined(PCLI_HAS_HYSTERIA2)
    hy2.DriveAll(&pfds);
#endif
#if defined(PCLI_HAS_HY2MESH)
    hy2m.DriveAll(&pfds);
#endif
#if defined(PCLI_HAS_TUIC)
    tuic.DriveAll(&pfds);
#endif
#if defined(PCLI_HAS_XHTTP)
    xhttp.DriveAll();
#endif
    mixed.Dispatch(pfds);
    api.Drive(pfds);
#if defined(PCLI_HAS_HYSTERIA2)
    hy2.DriveAll(nullptr, false);
#endif
#if defined(PCLI_HAS_HY2MESH)
    hy2m.DriveAll(nullptr, false);
#endif
#if defined(PCLI_HAS_TUIC)
    tuic.DriveAll(nullptr, false);
#endif
#if defined(PCLI_HAS_XHTTP)
    xhttp.DriveAll();
#endif
  }

  mixed.DropAll();
  api.Stop();
#if defined(PCLI_HAS_XHTTP)
  pcli::stack::XhttpPool::SetCurrent(nullptr);
#endif
  LOGI("RunMixedEmbedded: stopped cleanly");
  return 0;
}
#endif

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  g_vm = vm;
  JNIEnv* env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env != nullptr) {
    jclass cls = env->FindClass("io/github/acidefluorhydrique/geminiassist/pcli/PcliBridge");
    if (cls != nullptr) {
      g_bridge_class = static_cast<jclass>(env->NewGlobalRef(cls));
      g_log_method = env->GetStaticMethodID(cls, "onNativeLog", "(ILjava/lang/String;)V");
      env->DeleteLocalRef(cls);
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
  }
#if !defined(PCLI_ANDROID_STUB) && defined(__ANDROID__)
  pcli::log::SetAndroidSink(&NativeLogSink);
#endif
  if (!g_detach_key_ready.load(std::memory_order_acquire)) {
    if (::pthread_key_create(&g_jni_detach_key, &DetachThreadDestructor) == 0) {
      g_detach_key_ready.store(true, std::memory_order_release);
    } else {
      LOGW("JNI_OnLoad: pthread_key_create failed");
    }
  }
  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* /*reserved*/) {
#if !defined(PCLI_ANDROID_STUB) && defined(__ANDROID__)
  pcli::log::SetAndroidSink(nullptr);
#endif
  JNIEnv* env = nullptr;
  if (g_bridge_class && vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
    env->DeleteGlobalRef(g_bridge_class);
  }
  g_bridge_class = nullptr;
  g_log_method = nullptr;
  if (g_detach_key_ready.exchange(false, std::memory_order_acq_rel)) {
    ::pthread_key_delete(g_jni_detach_key);
  }
  g_vm = nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_acidefluorhydrique_geminiassist_pcli_PcliBridge_nativeVersion(JNIEnv* env, jclass /*clazz*/) {
#if defined(PCLI_ANDROID_STUB)
  return env->NewStringUTF("0.0.0-stub");
#else
  return env->NewStringUTF(pcli::kVersionString);
#endif
}

extern "C" JNIEXPORT jint JNICALL
Java_io_github_acidefluorhydrique_geminiassist_pcli_PcliBridge_nativeStartMixed(
    JNIEnv* env, jclass /*clazz*/, jstring configPath) {
  bool expected = false;
  if (!g_running.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
    LOGW("nativeStartMixed: already running");
    return -EBUSY;
  }
  RunGuard guard;

  const std::string cfg_path = JStringToStdString(env, configPath);
  if (cfg_path.empty()) {
    LOGE("nativeStartMixed: configPath is empty");
    return -EINVAL;
  }

#if defined(PCLI_ANDROID_STUB)
  LOGW("nativeStartMixed: built in STUB mode (config=%s)", cfg_path.c_str());
  return -ENOSYS;
#else
  pcli::stack::ResetStop();
  LOGI("nativeStartMixed: starting mixed proxy with config=%s", cfg_path.c_str());
  const int rc = RunMixedEmbedded(cfg_path);
  LOGI("nativeStartMixed: exited with rc=%d", rc);
  return static_cast<jint>(rc);
#endif
}

extern "C" JNIEXPORT void JNICALL
Java_io_github_acidefluorhydrique_geminiassist_pcli_PcliBridge_nativeStop(JNIEnv* /*env*/, jclass /*clazz*/) {
#if defined(PCLI_ANDROID_STUB)
  LOGW("nativeStop: stub mode");
#else
  LOGI("nativeStop: requesting stop");
  pcli::stack::RequestStop();
#endif
}

extern "C" JNIEXPORT void JNICALL
Java_io_github_acidefluorhydrique_geminiassist_pcli_PcliBridge_nativeReload(JNIEnv* /*env*/, jclass /*clazz*/) {
#if defined(PCLI_ANDROID_STUB)
  LOGW("nativeReload: stub mode");
#else
  LOGI("nativeReload: requesting reload");
  pcli::stack::RequestReload();
#endif
}

extern "C" JNIEXPORT jboolean JNICALL
Java_io_github_acidefluorhydrique_geminiassist_pcli_PcliBridge_nativeIsRunning(JNIEnv* /*env*/, jclass /*clazz*/) {
  return g_running.load(std::memory_order_acquire) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_github_acidefluorhydrique_geminiassist_pcli_PcliBridge_nativeCheckConfig(
    JNIEnv* env, jclass /*clazz*/, jstring configPath) {
  const std::string cfg_path = JStringToStdString(env, configPath);
  if (cfg_path.empty()) {
    return env->NewStringUTF("config path is empty");
  }
#if defined(PCLI_ANDROID_STUB)
  return env->NewStringUTF("libpcli_jni built in stub mode");
#else
  if (::access(cfg_path.c_str(), R_OK) != 0) {
    const std::string msg = std::string("cannot read config file: ") + std::strerror(errno);
    return env->NewStringUTF(msg.c_str());
  }
  pcli::route::Table table;
  if (!table.LoadFile(cfg_path, true)) {
    return env->NewStringUTF("invalid pcli configuration");
  }
  return env->NewStringUTF("");
#endif
}
