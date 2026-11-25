package io.github.acidefluorhydrique.geminiassist.pcli

import java.util.ArrayDeque

object PcliBridge {
    private const val MAX_LOG_LINES = 200
    private val logLock = Any()
    private val logBuffer = ArrayDeque<String>(MAX_LOG_LINES)

    val isNativeLoaded: Boolean
    val loadError: String?

    init {
        var loaded = false
        var error: String? = null
        try {
            System.loadLibrary("pcli_jni")
            loaded = true
        } catch (e: UnsatisfiedLinkError) {
            error = e.message ?: e.toString()
        }
        isNativeLoaded = loaded
        loadError = error
    }

    @JvmStatic
    fun onNativeLog(level: Int, message: String) {
        val tag = arrayOf("D", "I", "W", "E").getOrElse(level) { "I" }
        appendLog("[$tag] $message")
    }

    fun appendLog(line: String) {
        synchronized(logLock) {
            if (logBuffer.size >= MAX_LOG_LINES) {
                logBuffer.removeFirst()
            }
            logBuffer.addLast(line)
        }
    }

    fun recentLogs(): List<String> = synchronized(logLock) { logBuffer.toList() }

    fun clearLogs() {
        synchronized(logLock) { logBuffer.clear() }
    }

    @JvmStatic
    external fun nativeVersion(): String

    @JvmStatic
    external fun nativeStartMixed(configPath: String): Int

    @JvmStatic
    external fun nativeStop()

    @JvmStatic
    external fun nativeReload()

    @JvmStatic
    external fun nativeIsRunning(): Boolean

    @JvmStatic
    external fun nativeCheckConfig(configPath: String): String

    fun version(): String {
        if (!isNativeLoaded) return "native-not-loaded"
        return runCatching { nativeVersion() }
            .getOrElse { "error: ${it.message ?: it.javaClass.simpleName}" }
    }

    fun startMixed(configPath: String): Int {
        if (!isNativeLoaded) return -1
        return nativeStartMixed(configPath)
    }

    fun stop() {
        if (!isNativeLoaded) return
        nativeStop()
    }

    fun reload() {
        if (!isNativeLoaded) return
        nativeReload()
    }

    fun isRunning(): Boolean {
        if (!isNativeLoaded) return false
        return runCatching { nativeIsRunning() }.getOrDefault(false)
    }

    fun checkConfig(configPath: String): String {
        if (!isNativeLoaded) {
            return "Native library pcli_jni not loaded: ${loadError ?: "unknown error"}"
        }
        return runCatching { nativeCheckConfig(configPath) }
            .getOrElse { "Config check failed: ${it.message ?: it.javaClass.simpleName}" }
    }
}
