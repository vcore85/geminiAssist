package io.github.acidefluorhydrique.geminiassist.pcli

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.UUID

data class ProxySettings(
    val enabled: Boolean = false,
    val mixedPort: Int = 15330,
    val apiPort: Int = 19090,
    val apiSecret: String = "",
    val subscriptionUrl: String = ""
)

data class ProxyProfile(
    val id: String,
    val name: String,
    val protocol: String = "",
    val serverSummary: String = "",
    val subscriptionUrl: String = "",
    val shareLink: String = "",
    val configJson: String = "",
    val lastDelayMs: Int? = null,
    val updatedAt: Long = System.currentTimeMillis()
)

data class ImportSummary(
    val importedCount: Int,
    val failedCount: Int,
    val firstProfile: ProxyProfile?
)

class PcliStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("pcli_proxy_prefs", Context.MODE_PRIVATE)
    private val profilesFile = File(appContext.filesDir, "pcli_profiles.json")
    private val activeConfigFile = File(appContext.filesDir, "pcli_active_config.json")
    private val lock = Any()

    fun loadSettings(): ProxySettings {
        return ProxySettings(
            enabled = prefs.getBoolean("enabled", false),
            mixedPort = prefs.getInt("mixed_port", 15330).coerceIn(1024, 65535),
            apiPort = prefs.getInt("api_port", 19090).coerceIn(1024, 65535),
            apiSecret = prefs.getString("api_secret", "").orEmpty(),
            subscriptionUrl = prefs.getString("subscription_url", "").orEmpty()
        )
    }

    fun saveSettings(settings: ProxySettings) {
        prefs.edit()
            .putBoolean("enabled", settings.enabled)
            .putInt("mixed_port", settings.mixedPort.coerceIn(1024, 65535))
            .putInt("api_port", settings.apiPort.coerceIn(1024, 65535))
            .putString("api_secret", settings.apiSecret)
            .putString("subscription_url", settings.subscriptionUrl.trim())
            .apply()
    }

    fun loadProfiles(): List<ProxyProfile> = synchronized(lock) { readProfilesLocked() }

    fun getActiveProfileId(): String? = prefs.getString("active_profile_id", null)

    fun getActiveProfile(): ProxyProfile? {
        val list = loadProfiles()
        val id = getActiveProfileId()
        return list.firstOrNull { it.id == id } ?: list.firstOrNull()
    }

    fun selectProfile(id: String) {
        prefs.edit().putString("active_profile_id", id).apply()
    }

    fun updateDelay(id: String, delayMs: Int) {
        synchronized(lock) {
            val list = readProfilesLocked().toMutableList()
            val idx = list.indexOfFirst { it.id == id }
            if (idx >= 0) {
                list[idx] = list[idx].copy(lastDelayMs = delayMs)
                writeProfilesLocked(list)
            }
        }
    }

    fun deleteProfile(id: String) {
        synchronized(lock) {
            val remaining = readProfilesLocked().filterNot { it.id == id }
            writeProfilesLocked(remaining)
            if (getActiveProfileId() == id) {
                prefs.edit().putString("active_profile_id", remaining.firstOrNull()?.id).apply()
            }
        }
    }

    fun clearAllProfiles() {
        synchronized(lock) {
            writeProfilesLocked(emptyList())
            prefs.edit().remove("active_profile_id").apply()
        }
    }

    fun importFromText(text: String, subscriptionUrl: String = ""): ImportSummary {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return ImportSummary(0, 0, null)

        // Raw JSON single profile
        if (trimmed.startsWith("{")) {
            val formatted = runCatching { JSONObject(trimmed).toString(2) }.getOrDefault(trimmed)
            val name = extractJsonProfileName(trimmed, subscriptionUrl)
            val profile = ProxyProfile(
                id = UUID.randomUUID().toString(),
                name = name,
                protocol = "json",
                serverSummary = "自定义 JSON 配置",
                subscriptionUrl = subscriptionUrl.trim(),
                shareLink = "",
                configJson = formatted
            )
            synchronized(lock) {
                val list = readProfilesLocked().toMutableList()
                val existingIdx = if (subscriptionUrl.isNotBlank()) {
                    list.indexOfFirst { it.subscriptionUrl == subscriptionUrl.trim() && it.shareLink.isEmpty() }
                } else -1
                if (existingIdx >= 0) {
                    list[existingIdx] = profile.copy(id = list[existingIdx].id)
                } else {
                    list.add(profile)
                }
                writeProfilesLocked(list)
                if (getActiveProfileId() == null) {
                    selectProfile(if (existingIdx >= 0) list[existingIdx].id else profile.id)
                }
            }
            return ImportSummary(1, 0, profile)
        }

        val parsed = ShareLinkCodec.parseLinks(trimmed)
        if (parsed.nodes.isEmpty()) {
            return ImportSummary(0, parsed.bad, null)
        }

        val settings = loadSettings()
        val imported = mutableListOf<ProxyProfile>()
        synchronized(lock) {
            val list = readProfilesLocked().toMutableList()
            val subUrl = subscriptionUrl.trim()
            if (subUrl.isNotEmpty()) {
                // Replace old nodes from the same subscription URL on refresh
                list.removeAll { it.subscriptionUrl == subUrl }
            }
            parsed.nodes.forEachIndexed { index, node ->
                val rawLink = parsed.rawLinks.getOrElse(index) { "" }
                val normalizedLink = ShareLinkCodec.buildLink(node) ?: rawLink
                val profileName = node.label.ifBlank { "${node.type}-${node.address}" }
                val summary = if (node.address.isNotBlank() && node.port.isNotBlank()) {
                    "${node.address}:${node.port}"
                } else {
                    node.address.ifBlank { node.type }
                }
                val existingIdx = list.indexOfFirst {
                    it.shareLink.isNotBlank() && it.shareLink == normalizedLink
                }
                val profile = ProxyProfile(
                    id = if (existingIdx >= 0) list[existingIdx].id else UUID.randomUUID().toString(),
                    name = profileName,
                    protocol = node.type,
                    serverSummary = summary,
                    subscriptionUrl = subUrl,
                    shareLink = normalizedLink,
                    configJson = PcliConfigGenerator.generateFromNode(node, settings)
                )
                if (existingIdx >= 0) {
                    list[existingIdx] = profile
                } else {
                    list.add(profile)
                }
                imported.add(profile)
            }
            writeProfilesLocked(list)
            val activeId = getActiveProfileId()
            if (activeId == null || list.none { it.id == activeId }) {
                imported.firstOrNull()?.let { selectProfile(it.id) }
            }
        }
        return ImportSummary(imported.size, parsed.bad, imported.firstOrNull())
    }

    suspend fun importFromSubscriptionUrl(
        url: String,
        useLocalProxyPort: Int? = null
    ): Result<ImportSummary> = withContext(Dispatchers.IO) {
        runCatching {
            val trimmedUrl = url.trim()
            require(trimmedUrl.startsWith("http://") || trimmedUrl.startsWith("https://")) {
                "订阅地址必须以 http:// 或 https:// 开头"
            }
            val proxy = if (useLocalProxyPort != null && useLocalProxyPort in 1024..65535) {
                Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", useLocalProxyPort))
            } else {
                Proxy.NO_PROXY
            }
            val conn = (URL(trimmedUrl).openConnection(proxy) as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = 15_000
                readTimeout = 20_000
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "geminiAssist-pcli/1.0")
                setRequestProperty("Accept", "text/plain, application/json, */*")
            }
            try {
                val code = conn.responseCode
                val stream = if (code in 200..299) conn.inputStream else conn.errorStream
                val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
                if (code !in 200..299) {
                    throw IOException("HTTP $code: ${body.take(200)}")
                }
                if (body.isBlank()) {
                    throw IOException("订阅返回内容为空")
                }
                val summary = importFromText(body, subscriptionUrl = trimmedUrl)
                if (summary.importedCount <= 0) {
                    throw IOException("未从订阅中解析出有效节点")
                }
                val currentSettings = loadSettings()
                saveSettings(currentSettings.copy(subscriptionUrl = trimmedUrl))
                summary
            } finally {
                conn.disconnect()
            }
        }
    }

    fun writeActiveConfigFile(): File? {
        val active = getActiveProfile() ?: return null
        val settings = loadSettings()
        val json = PcliConfigGenerator.generateForProfile(active, settings)
        synchronized(lock) {
            activeConfigFile.writeText(json, Charsets.UTF_8)
        }
        return activeConfigFile
    }

    private fun extractJsonProfileName(json: String, subUrl: String): String {
        val host = runCatching { if (subUrl.isNotBlank()) URL(subUrl).host else null }.getOrNull()
        return host?.ifBlank { null } ?: "JSON 配置"
    }

    private fun readProfilesLocked(): List<ProxyProfile> {
        if (!profilesFile.isFile) return emptyList()
        return runCatching {
            val arr = JSONArray(profilesFile.readText(Charsets.UTF_8))
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.optJSONObject(i) ?: continue
                    val id = o.optString("id", "").trim()
                    if (id.isEmpty()) continue
                    add(
                        ProxyProfile(
                            id = id,
                            name = o.optString("name", "Unnamed"),
                            protocol = o.optString("protocol", ""),
                            serverSummary = o.optString("serverSummary", ""),
                            subscriptionUrl = o.optString("subscriptionUrl", ""),
                            shareLink = o.optString("shareLink", ""),
                            configJson = o.optString("configJson", ""),
                            lastDelayMs = if (o.has("lastDelayMs") && !o.isNull("lastDelayMs")) {
                                o.optInt("lastDelayMs")
                            } else null,
                            updatedAt = o.optLong("updatedAt", System.currentTimeMillis())
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun writeProfilesLocked(list: List<ProxyProfile>) {
        val arr = JSONArray()
        for (p in list) {
            arr.put(JSONObject().apply {
                put("id", p.id)
                put("name", p.name)
                put("protocol", p.protocol)
                put("serverSummary", p.serverSummary)
                put("subscriptionUrl", p.subscriptionUrl)
                put("shareLink", p.shareLink)
                put("configJson", p.configJson)
                if (p.lastDelayMs != null) put("lastDelayMs", p.lastDelayMs)
                put("updatedAt", p.updatedAt)
            })
        }
        profilesFile.writeText(arr.toString(2), Charsets.UTF_8)
    }
}
