package io.github.acidefluorhydrique.geminiassist.pcli

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetSocketAddress
import java.net.Socket

enum class PcliStatus {
    STOPPED,
    STARTING,
    RUNNING,
    ERROR
}

data class PcliRuntimeState(
    val status: PcliStatus = PcliStatus.STOPPED,
    val activeProfileId: String? = null,
    val activeProfileName: String = "",
    val mixedPort: Int = 15330,
    val apiPort: Int = 19090,
    val errorMessage: String? = null,
    val exitProbe: ExitProbeResult? = null
)

object PcliRuntime {
    private const val TAG = "PcliRuntime"
    private val lock = Any()
    private var workerThread: Thread? = null

    private val _state = MutableStateFlow(PcliRuntimeState())
    val state: StateFlow<PcliRuntimeState> = _state.asStateFlow()

    @JvmStatic
    fun isProxyActive(): Boolean {
        return _state.value.status == PcliStatus.RUNNING && PcliBridge.isRunning()
    }

    @JvmStatic
    fun activeMixedPort(): Int = _state.value.mixedPort

    /**
     * Called from MainActivity.onCreate() before WebView.loadUrl() so that if proxy is enabled,
     * pcli starts and WebView proxy override is applied before the first request is sent.
     * Callback receives true if safe to load Gemini (either proxy disabled, or proxy active),
     * or false if proxy is enabled but failed to start (prevents leaking direct traffic/DNS).
     */
    @JvmStatic
    fun startIfEnabled(context: Context, onReady: java.util.function.Consumer<Boolean>?) {
        val store = PcliStore(context)
        val settings = store.loadSettings()
        if (!settings.enabled) {
            WebViewProxyManager.clearProxy { onReady?.accept(true) }
            return
        }
        val active = store.getActiveProfile()
        if (active == null) {
            onReady?.accept(false)
            return
        }
        if (isProxyActive() &&
            _state.value.activeProfileId == active.id &&
            _state.value.mixedPort == settings.mixedPort
        ) {
            WebViewProxyManager.applyProxy(settings.mixedPort) { onReady?.accept(true) }
            return
        }
        Thread({
            val ok = startSync(context)
            if (ok) {
                WebViewProxyManager.applyProxy(settings.mixedPort) { onReady?.accept(true) }
            } else {
                android.os.Handler(android.os.Looper.getMainLooper()).post {
                    onReady?.accept(false)
                }
            }
        }, "pcli-bootstrap").start()
    }

    fun startSync(context: Context): Boolean {
        val store = PcliStore(context)
        val settings = store.loadSettings()
        val active = store.getActiveProfile()
        if (active == null) {
            _state.value = PcliRuntimeState(
                status = PcliStatus.ERROR,
                mixedPort = settings.mixedPort,
                apiPort = settings.apiPort,
                errorMessage = "请先导入并选择一个节点"
            )
            return false
        }
        if (!PcliBridge.isNativeLoaded) {
            _state.value = PcliRuntimeState(
                status = PcliStatus.ERROR,
                activeProfileId = active.id,
                activeProfileName = active.name,
                mixedPort = settings.mixedPort,
                apiPort = settings.apiPort,
                errorMessage = "未加载 libpcli_jni.so: ${PcliBridge.loadError ?: "unknown"}"
            )
            return false
        }

        stopSync(clearWebViewProxy = false)

        val configFile = store.writeActiveConfigFile()
        if (configFile == null || !configFile.isFile) {
            _state.value = PcliRuntimeState(
                status = PcliStatus.ERROR,
                activeProfileId = active.id,
                activeProfileName = active.name,
                mixedPort = settings.mixedPort,
                apiPort = settings.apiPort,
                errorMessage = "生成 pcli 配置文件失败"
            )
            return false
        }

        val checkErr = PcliBridge.checkConfig(configFile.absolutePath)
        if (checkErr.isNotEmpty()) {
            _state.value = PcliRuntimeState(
                status = PcliStatus.ERROR,
                activeProfileId = active.id,
                activeProfileName = active.name,
                mixedPort = settings.mixedPort,
                apiPort = settings.apiPort,
                errorMessage = "配置校验失败: $checkErr"
            )
            return false
        }

        _state.value = PcliRuntimeState(
            status = PcliStatus.STARTING,
            activeProfileId = active.id,
            activeProfileName = active.name,
            mixedPort = settings.mixedPort,
            apiPort = settings.apiPort,
            errorMessage = null,
            exitProbe = null
        )

        val t = Thread({
            Log.i(TAG, "Starting pcli mixed engine with ${configFile.absolutePath}")
            val rc = PcliBridge.startMixed(configFile.absolutePath)
            Log.i(TAG, "pcli mixed engine exited with rc=$rc")
            val cur = _state.value
            if (cur.status != PcliStatus.STOPPED) {
                _state.value = cur.copy(
                    status = if (rc == 0) PcliStatus.STOPPED else PcliStatus.ERROR,
                    errorMessage = if (rc == 0) null else "pcli 异常退出 (rc=$rc)"
                )
            }
        }, "pcli-mixed-core").apply {
            isDaemon = true
        }

        synchronized(lock) {
            workerThread = t
            t.start()
        }

        val listening = waitForPortReady(settings.mixedPort, timeoutMs = 3000L)
        if (!listening || !PcliBridge.isRunning()) {
            stopSync(clearWebViewProxy = true)
            _state.value = PcliRuntimeState(
                status = PcliStatus.ERROR,
                activeProfileId = active.id,
                activeProfileName = active.name,
                mixedPort = settings.mixedPort,
                apiPort = settings.apiPort,
                errorMessage = "pcli 本地代理端口 127.0.0.1:${settings.mixedPort} 启动失败"
            )
            return false
        }

        WebViewProxyManager.applyProxyBlocking(settings.mixedPort)
        _state.value = PcliRuntimeState(
            status = PcliStatus.RUNNING,
            activeProfileId = active.id,
            activeProfileName = active.name,
            mixedPort = settings.mixedPort,
            apiPort = settings.apiPort,
            errorMessage = null,
            exitProbe = null
        )
        return true
    }

    fun stopSync(clearWebViewProxy: Boolean = true) {
        if (clearWebViewProxy) {
            WebViewProxyManager.clearProxy()
        }
        val t: Thread?
        synchronized(lock) {
            t = workerThread
            workerThread = null
        }
        if (PcliBridge.isRunning()) {
            PcliBridge.stop()
        }
        if (t != null && t.isAlive) {
            runCatching { t.join(2000L) }
        }
        _state.value = _state.value.copy(
            status = PcliStatus.STOPPED,
            errorMessage = null,
            exitProbe = null
        )
    }

    fun updateExitProbe(result: ExitProbeResult?) {
        _state.value = _state.value.copy(exitProbe = result)
    }

    private fun waitForPortReady(port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (PcliBridge.isRunning()) {
                val ok = runCatching {
                    Socket().use { s ->
                        s.connect(InetSocketAddress("127.0.0.1", port), 150)
                    }
                    true
                }.getOrDefault(false)
                if (ok) return true
            }
            try {
                Thread.sleep(60L)
            } catch (_: InterruptedException) {
                break
            }
        }
        return false
    }
}
