package io.github.acidefluorhydrique.geminiassist.pcli

import android.content.ContentValues
import android.content.Context
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import android.webkit.CookieManager
import android.widget.Toast
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewFeature
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object WebViewProxyManager {
    private const val TAG = "WebViewProxyManager"
    private val mainHandler = Handler(Looper.getMainLooper())
    private val downloadExecutor = Executors.newSingleThreadExecutor()

    @Volatile
    var isProxyOverrideApplied: Boolean = false
        private set

    fun isSupported(): Boolean {
        return WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)
    }

    /**
     * Applies WebView proxy override to route all WebView HTTP/HTTPS/WS traffic
     * through local pcli mixed inbound without TUN mode.
     */
    fun applyProxy(port: Int, onComplete: (() -> Unit)? = null) {
        if (!isSupported()) {
            Log.w(TAG, "WebView PROXY_OVERRIDE is not supported on this device")
            isProxyOverrideApplied = false
            onComplete?.let { mainHandler.post(it) }
            return
        }
        val config = ProxyConfig.Builder()
            .addProxyRule("http://127.0.0.1:$port")
            .addBypassRule("127.0.0.1")
            .addBypassRule("localhost")
            .build()

        mainHandler.post {
            try {
                ProxyController.getInstance().setProxyOverride(
                    config,
                    { runnable -> mainHandler.post(runnable) },
                    {
                        isProxyOverrideApplied = true
                        Log.i(TAG, "WebView proxy override applied: 127.0.0.1:$port")
                        onComplete?.invoke()
                    }
                )
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to apply WebView proxy override", e)
                isProxyOverrideApplied = false
                onComplete?.invoke()
            }
        }
    }

    fun applyProxyBlocking(port: Int, timeoutMs: Long = 2000L) {
        if (!isSupported()) return
        if (Looper.myLooper() == Looper.getMainLooper()) {
            applyProxy(port, null)
            return
        }
        val latch = CountDownLatch(1)
        applyProxy(port) { latch.countDown() }
        runCatching { latch.await(timeoutMs, TimeUnit.MILLISECONDS) }
    }

    fun clearProxy(onComplete: (() -> Unit)? = null) {
        if (!isSupported()) {
            isProxyOverrideApplied = false
            onComplete?.let { mainHandler.post(it) }
            return
        }
        mainHandler.post {
            try {
                ProxyController.getInstance().clearProxyOverride(
                    { runnable -> mainHandler.post(runnable) },
                    {
                        isProxyOverrideApplied = false
                        Log.i(TAG, "WebView proxy override cleared")
                        onComplete?.invoke()
                    }
                )
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to clear WebView proxy override", e)
                isProxyOverrideApplied = false
                onComplete?.invoke()
            }
        }
    }

    /**
     * Downloads a URL strictly through the local pcli mixed proxy and saves it to Downloads,
     * replacing system DownloadManager (which bypasses WebView proxy).
     */
    @JvmStatic
    fun downloadViaProxy(
        context: Context,
        url: String,
        filename: String,
        mimetype: String?,
        userAgent: String?,
        proxyPort: Int
    ) {
        val appContext = context.applicationContext
        val safeFilename = filename.ifBlank { "gemini_download_${System.currentTimeMillis()}" }
        val safeMime = mimetype?.takeIf { it.isNotBlank() } ?: "application/octet-stream"
        val cookie = CookieManager.getInstance().getCookie(url)

        mainHandler.post {
            Toast.makeText(appContext, "正在通过 pcli 下载: $safeFilename", Toast.LENGTH_SHORT).show()
        }

        downloadExecutor.execute {
            val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort))
            try {
                val conn = (URL(url).openConnection(proxy) as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 15_000
                    readTimeout = 60_000
                    instanceFollowRedirects = true
                    if (!cookie.isNullOrBlank()) setRequestProperty("Cookie", cookie)
                    if (!userAgent.isNullOrBlank()) setRequestProperty("User-Agent", userAgent)
                    setRequestProperty("Referer", url)
                }
                val bytes = try {
                    val code = conn.responseCode
                    if (code !in 200..299) {
                        throw IOException("HTTP $code")
                    }
                    conn.inputStream.use { it.readBytes() }
                } finally {
                    conn.disconnect()
                }
                val savedName = saveBytesToDownloads(appContext, bytes, safeFilename, safeMime)
                mainHandler.post {
                    Toast.makeText(appContext, "已下载: $savedName", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Proxied download failed for $url", e)
                mainHandler.post {
                    Toast.makeText(appContext, "下载失败: ${e.message ?: "网络错误"}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun saveBytesToDownloads(
        context: Context,
        bytes: ByteArray,
        filename: String,
        mimetype: String
    ): String {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, mimetype)
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val resolver = context.contentResolver
            val item = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: throw IOException("MediaStore insert failed")
            try {
                resolver.openOutputStream(item)?.use { it.write(bytes) }
                    ?: throw IOException("Cannot open output stream")
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(item, values, null, null)
            } catch (e: IOException) {
                resolver.delete(item, null, null)
                throw e
            }
            return filename
        } else {
            @Suppress("DEPRECATION")
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (!dir.exists() && !dir.mkdirs()) throw IOException("Cannot create Downloads dir")
            var file = File(dir, filename)
            val dot = filename.lastIndexOf('.')
            val base = if (dot > 0) filename.substring(0, dot) else filename
            val ext = if (dot > 0) filename.substring(dot) else ""
            var i = 1
            while (file.exists()) {
                file = File(dir, "$base ($i)$ext")
                i++
            }
            FileOutputStream(file).use { it.write(bytes) }
            MediaScannerConnection.scanFile(context, arrayOf(file.absolutePath), arrayOf(mimetype), null)
            return file.name
        }
    }
}
