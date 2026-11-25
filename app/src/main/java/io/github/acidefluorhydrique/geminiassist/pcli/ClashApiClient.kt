package io.github.acidefluorhydrique.geminiassist.pcli

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.net.URLEncoder

class ClashApiClient(
    private val host: String = "127.0.0.1",
    private val port: Int = 19090,
    private val secret: String = ""
) {
    private val baseUrl: String
        get() = "http://$host:$port"

    suspend fun testDelay(
        proxyName: String = "main-out",
        url: String = "https://www.gstatic.com/generate_204",
        timeoutMs: Int = 5000
    ): Result<Int> = withContext(Dispatchers.IO) {
        runCatching {
            val encodedProxy = URLEncoder.encode(proxyName, "UTF-8").replace("+", "%20")
            val encodedUrl = URLEncoder.encode(url, "UTF-8")
            val body = request(
                method = "GET",
                path = "/proxies/$encodedProxy/delay?url=$encodedUrl&timeout=$timeoutMs",
                readTimeoutMs = timeoutMs + 3000
            )
            val obj = JSONObject(body)
            if (!obj.has("delay")) {
                throw IOException("Missing delay in response: $body")
            }
            obj.getInt("delay")
        }
    }

    suspend fun fetchVersion(): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val body = request("GET", "/version")
            runCatching { JSONObject(body).optString("version", body) }.getOrDefault(body)
        }
    }

    private fun request(
        method: String,
        path: String,
        connectTimeoutMs: Int = 3000,
        readTimeoutMs: Int = 6000
    ): String {
        val conn = (URL("$baseUrl$path").openConnection(Proxy.NO_PROXY) as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
            setRequestProperty("Accept", "application/json")
            if (secret.isNotBlank()) {
                setRequestProperty("Authorization", "Bearer $secret")
            }
        }
        try {
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            if (code !in 200..299) {
                throw IOException("HTTP $code: $body")
            }
            return body
        } finally {
            conn.disconnect()
        }
    }
}
