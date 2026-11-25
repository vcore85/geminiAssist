package io.github.acidefluorhydrique.geminiassist.pcli

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import java.util.Locale

data class ExitProbeResult(
    val delayMs: Int = -1,
    val exitIp: String? = null,
    val country: String? = null,
    val countryCode: String? = null,
    val flagEmoji: String? = null,
    val isp: String? = null,
    val error: String? = null,
    val testedAtMillis: Long = System.currentTimeMillis()
)

object NodeProbeHelper {
    private val NON_NODE_TYPES = setOf("selector", "urltest", "fallback", "direct", "reject", "block")

    private val COUNTRY_ZH_MAP = mapOf(
        "CN" to "中国大陆", "HK" to "中国香港", "TW" to "中国台湾", "MO" to "中国澳门",
        "US" to "美国", "JP" to "日本", "SG" to "新加坡", "KR" to "韩国",
        "GB" to "英国", "DE" to "德国", "FR" to "法国", "NL" to "荷兰",
        "CA" to "加拿大", "AU" to "澳大利亚", "RU" to "俄罗斯", "IN" to "印度",
        "TH" to "泰国", "VN" to "越南", "MY" to "马来西亚", "PH" to "菲律宾",
        "ID" to "印度尼西亚", "TR" to "土耳其", "BR" to "巴西", "CH" to "瑞士",
        "SE" to "瑞典", "FI" to "芬兰", "IT" to "意大利", "ES" to "西班牙",
        "PL" to "波兰", "AE" to "阿联酋"
    )

    private data class GeoIpInfo(
        val ip: String,
        val country: String,
        val countryCode: String,
        val isp: String,
        val elapsedMs: Int
    )

    fun flagEmoji(countryCode: String?): String {
        val code = countryCode?.trim()?.uppercase(Locale.US) ?: return ""
        if (code.length != 2 || code[0] !in 'A'..'Z' || code[1] !in 'A'..'Z') return ""
        val first = Character.toChars(0x1F1E6 + (code[0] - 'A'))
        val second = Character.toChars(0x1F1E6 + (code[1] - 'A'))
        return String(first) + String(second)
    }

    fun countryNameZh(countryCode: String?, fallback: String = ""): String {
        val code = countryCode?.trim()?.uppercase(Locale.US).orEmpty()
        if (code.length == 2) {
            COUNTRY_ZH_MAP[code]?.let { return it }
            val localized = Locale("", code).getDisplayCountry(Locale.SIMPLIFIED_CHINESE).trim()
            if (localized.isNotEmpty() && !localized.equals(code, ignoreCase = true)) {
                return localized
            }
        }
        return fallback
    }

    fun extractServerPort(profile: ProxyProfile): Pair<String, Int>? {
        val shareLink = profile.shareLink.trim()
        if (shareLink.isNotEmpty()) {
            val node = ShareLinkCodec.parseLink(shareLink)
            if (node != null) {
                val host = node.address.trim()
                val port = node.port.trim().toIntOrNull() ?: -1
                if (host.isNotEmpty() && port in 1..65535) return host to port
            }
        }
        val configJson = profile.configJson.trim()
        if (configJson.isEmpty()) return null
        return runCatching {
            val root = JSONObject(configJson)
            val outbounds = root.optJSONArray("outbounds") ?: return@runCatching null
            for (i in 0 until outbounds.length()) {
                val ob = outbounds.optJSONObject(i) ?: continue
                val type = ob.optString("type", "").trim().lowercase(Locale.US)
                if (type in NON_NODE_TYPES) continue
                val server = ob.optString("server", "").trim()
                val port = ob.optInt("port", -1)
                if (server.isNotEmpty() && port in 1..65535) return@runCatching server to port
            }
            null
        }.getOrNull()
    }

    suspend fun testTcpDelay(profile: ProxyProfile, timeoutMs: Int = 3500): Int =
        withContext(Dispatchers.IO) {
            val (server, port) = extractServerPort(profile) ?: return@withContext -1
            runCatching {
                val startNanos = System.nanoTime()
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(server, port), timeoutMs)
                }
                ((System.nanoTime() - startNanos) / 1_000_000L).toInt().coerceAtLeast(1)
            }.getOrDefault(-1)
        }

    /**
     * Probes real proxy latency (via Clash API) and exit IP/GeoIP strictly through the
     * local pcli HTTP mixed proxy (never falls back to direct).
     */
    suspend fun probeConnectedExit(
        clashClient: ClashApiClient,
        mixedPort: Int,
        timeoutMs: Int = 8000
    ): ExitProbeResult = withContext(Dispatchers.IO) {
        val clashDelay = clashClient.testDelay("main-out", timeoutMs = 5000).getOrDefault(-1)

        val endpoints = listOf(
            "https://ipwho.is/?lang=zh-CN",
            "https://api.ip.sb/geoip",
            "https://ipinfo.io/json",
            "https://api.ipify.org?format=json"
        )

        val proxy = Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", mixedPort))
        var geoInfo: GeoIpInfo? = null
        var lastError: String? = null

        for (endpoint in endpoints) {
            val result = runCatching {
                val startNanos = System.nanoTime()
                val body = fetchViaProxy(endpoint, proxy, timeoutMs)
                val elapsedMs = ((System.nanoTime() - startNanos) / 1_000_000L).toInt().coerceAtLeast(1)
                parseGeoIp(endpoint, body, elapsedMs)
            }
            result.onSuccess { info ->
                if (info != null && info.ip.isNotBlank()) {
                    geoInfo = info
                } else {
                    lastError = "空响应: $endpoint"
                }
            }.onFailure { err ->
                lastError = err.message ?: err.javaClass.simpleName
            }
            if (geoInfo != null) break
        }

        val info = geoInfo
        val finalDelay = if (clashDelay >= 0) clashDelay else (info?.elapsedMs ?: -1)
        val code = info?.countryCode?.trim()?.uppercase(Locale.US).orEmpty()
        val resolvedCountry = if (info != null) {
            countryNameZh(code, info.country).ifBlank { null }
        } else null
        val resolvedFlag = if (code.isNotEmpty()) flagEmoji(code).ifBlank { null } else null

        ExitProbeResult(
            delayMs = finalDelay,
            exitIp = info?.ip?.ifBlank { null },
            country = resolvedCountry,
            countryCode = code.ifBlank { null },
            flagEmoji = resolvedFlag,
            isp = info?.isp?.ifBlank { null },
            error = if (info == null && finalDelay < 0) (lastError ?: "探测失败") else null
        )
    }

    private fun fetchViaProxy(urlString: String, proxy: Proxy, timeoutMs: Int): String {
        val conn = (URL(urlString).openConnection(proxy) as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "geminiAssist-pcli/1.0")
            setRequestProperty("Accept", "application/json")
        }
        try {
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            if (code !in 200..299) {
                throw IOException("HTTP $code")
            }
            return body
        } finally {
            conn.disconnect()
        }
    }

    private fun parseGeoIp(endpoint: String, body: String, elapsedMs: Int): GeoIpInfo? {
        val obj = JSONObject(body)
        return when {
            endpoint.contains("ipwho.is") -> {
                if (obj.has("success") && !obj.optBoolean("success", true)) return null
                val ip = obj.optString("ip", "").trim()
                if (ip.isEmpty()) return null
                val connObj = obj.optJSONObject("connection")
                val isp = connObj?.optString("isp", "").orEmpty()
                    .ifBlank { connObj?.optString("org", "").orEmpty() }
                GeoIpInfo(
                    ip = ip,
                    country = obj.optString("country", "").trim(),
                    countryCode = obj.optString("country_code", "").trim(),
                    isp = isp.trim(),
                    elapsedMs = elapsedMs
                )
            }
            endpoint.contains("ip.sb") -> {
                val ip = obj.optString("ip", "").trim()
                if (ip.isEmpty()) return null
                GeoIpInfo(
                    ip = ip,
                    country = obj.optString("country", "").trim(),
                    countryCode = obj.optString("country_code", "").trim(),
                    isp = obj.optString("isp", "").trim()
                        .ifBlank { obj.optString("organization", "").trim() },
                    elapsedMs = elapsedMs
                )
            }
            endpoint.contains("ipinfo.io") -> {
                val ip = obj.optString("ip", "").trim()
                if (ip.isEmpty()) return null
                val cc = obj.optString("country", "").trim()
                GeoIpInfo(
                    ip = ip,
                    country = cc,
                    countryCode = cc,
                    isp = obj.optString("org", "").trim(),
                    elapsedMs = elapsedMs
                )
            }
            else -> {
                val ip = obj.optString("ip", "").trim()
                if (ip.isEmpty()) return null
                GeoIpInfo(ip = ip, country = "", countryCode = "", isp = "", elapsedMs = elapsedMs)
            }
        }
    }
}
