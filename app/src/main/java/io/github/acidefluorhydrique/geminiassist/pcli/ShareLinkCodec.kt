package io.github.acidefluorhydrique.geminiassist.pcli

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.URLEncoder
import java.util.Base64

data class ParsedNode(
    val type: String,
    val label: String = "",
    val address: String = "",
    val port: String = "",
    val uuid: String = "",
    val password: String = "",
    val username: String = "",
    // VLESS
    val flow: String = "",
    // VMess
    val vmessSecurity: String = "",
    val vmessAlterId: String = "",
    // Shadowsocks
    val ssMethod: String = "",
    // TLS & REALITY
    val tls: Boolean = false,
    val tlsSni: String = "",
    val tlsAlpn: String = "",
    val tlsInsecure: Boolean = false,
    val reality: Boolean = false,
    val realityPublicKey: String = "",
    val realityShortId: String = "",
    val realityFingerprint: String = "",
    // Transport
    val transport: String = "tcp",
    val wsPath: String = "",
    val wsHost: String = "",
    val grpcService: String = "",
    val xhttpPath: String = "",
    val xhttpHost: String = "",
    val xhttpMode: String = "",
    val xhttpExtra: String = "",
    val xhttpIpPool: String = "",
    val xhttpIpPoolParallel: String = "",
    val xhttpIpPoolHop: String = "",
    val xhttpIpPoolProbe: String = "",
    val xhttpIpPoolTries: String = "",
    val xhttpIpPoolDraining: String = "",
    val xhttpIpPoolDrain: String = "",
    val xhttpIpPoolAffinity: String = "",
    // Hysteria2
    val hy2ObfsType: String = "",
    val hy2ObfsPassword: String = "",
    val hy2UpMbps: String = "",
    val hy2DownMbps: String = "",
    val hy2Cc: String = "",
    val hy2UpCc: String = "",
    val hy2DownCc: String = "",
    val hy2Conns: String = "",
    val hy2Ports: String = "",
    // Hysteria2Mesh / Hy2MeshLite
    val meshUp: List<String> = emptyList(),
    val meshDown: List<String> = emptyList(),
    val hy2mPaths: String = "",
    val hy2mPathsUp: String = "",
    val hy2mPathsDown: String = "",
    val hy2mFlowPaths: String = "",
    val hy2mTransportMode: String = "",
    val hy2mRelayPorts: String = "",
    val hy2mSessions: String = "",
    val hy2mHopS: String = "",
    val hy2mFec: String = "",
    // TCPMesh
    val tcpmeshRelays: List<String> = emptyList(),
    val tcpmeshSessions: String = "",
    val tcpmeshStripe: String = "",
    val tcpmeshFailoverUp: String = "",
    val tcpmeshStreamWinMb: String = "",
    val tcpmeshSessionMemMb: String = "",
    val tcpmeshLazyScale: String = "",
    val tcpmeshRotateS: String = "",
    // TUIC
    val tuicCc: String = "",
    val tuicUdpRelayMode: String = "",
    val tuicConns: String = "",
    val tuicPorts: String = "",
    // MPQUIC
    val mpqEnable: Boolean = false,
    val mpqPorts: String = "",
    val mpqToken: String = "",
    val mpqObfs: String = "",
    val mpqPaths: String = "",
    val mpqServer: String = "",
    val mpqSni: String = "",
    val mpqCa: String = "",
    val mpqInsecure: Boolean = false,
    val mpqUpstream: String = "",
    val mpqReorderMs: String = "",
    val mpqCc: String = "",
    val mpqAlpn: String = "",
    val mpqDown: String = ""
)

data class ParsedLinksResult(
    val nodes: List<ParsedNode>,
    val rawLinks: List<String>,
    val bad: Int
)

object ShareLinkCodec {

    private val MARKDOWN_LINK_REGEX = Regex("""\[([^\[\]\s]+)\]\((https?://[^()\s]*)\)""", RegexOption.IGNORE_CASE)
    private val SCHEME_REGEX = Regex("""^([a-z0-9]+)://(.+)$""", RegexOption.IGNORE_CASE)
    private val DIGITS_REGEX = Regex("""^[0-9]+$""")
    private val LEADING_DIGITS_REGEX = Regex("""^\d+""")
    private val IPV4_REGEX = Regex("""^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$""")
    private val TCPMESH_PUBKEY_REGEX = Regex("""^[A-Za-z0-9_+\/-]{43}={0,1}$""")
    private val TCPMESH_SID_REGEX = Regex("""^[0-9a-fA-F]{0,16}$""")
    private val TCPMESH_FP_KNOWN = setOf("chrome", "firefox", "safari", "edge", "ios", "qq", "360", "random", "randomized")

    private val MESH_NUMBERS = listOf(
        Triple("hy2m_paths", 1, 32),
        Triple("hy2m_paths_up", 0, 32),
        Triple("hy2m_paths_down", 0, 32),
        Triple("hy2m_flow_paths", 1, 8),
        Triple("hy2m_relay_ports", 1, 4),
        Triple("hy2m_sessions", 1, 8),
        Triple("hy2m_hop_s", 0, 3600)
    )

    private val HY2MLITE_NUMBERS = listOf(
        Triple("hy2m_paths", 1, 32),
        Triple("hy2m_paths_up", 0, 32),
        Triple("hy2m_paths_down", 0, 32),
        Triple("hy2m_sessions", 1, 8),
        Triple("hy2m_hop_s", 0, 3600)
    )

    private val TCPMESH_NUMBERS = listOf(
        Triple("tcpmesh_sessions", 1, 8),
        Triple("tcpmesh_stream_win_mb", 1, 64),
        Triple("tcpmesh_session_mem_mb", 4, 256),
        Triple("tcpmesh_rotate_s", 0, 86400)
    )

    private data class SplitUrlResult(
        val label: String,
        val query: Map<String, String>,
        val relays: List<String>,
        val user: String,
        val host: String,
        val port: String
    )

    internal data class HostPort(val host: String, val port: String)

    internal data class ParsedTcpMeshRelay(
        val addr: String = "",
        val host: String = "",
        val port: String = "",
        val sni: String = "",
        val role: String = "both",
        val subflowsUp: Int? = null,
        val subflowsDown: Int? = null,
        val relayGroup: Int? = null,
        val tag: String = "",
        val error: String? = null
    )

    fun unwrapMarkdownLinks(s: String): String {
        return MARKDOWN_LINK_REGEX.replace(s) { m ->
            val text = m.groupValues[1]
            val href = m.groupValues[2]
            val bare = href.replace(Regex("^https?://", RegexOption.IGNORE_CASE), "").removeSuffix("/")
            if (bare.equals(text, ignoreCase = true) || href == text) text else m.value
        }
    }

    fun b64decode(s: String): String? {
        var clean = s.trim()
            .replace('-', '+')
            .replace('_', '/')
            .replace(Regex("""\s+"""), "")
        if (clean.isEmpty()) return null
        while (clean.length % 4 != 0) {
            clean += "="
        }
        return runCatching {
            String(Base64.getDecoder().decode(clean), Charsets.UTF_8)
        }.getOrNull()
    }

    fun b64encode(s: String): String {
        return Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    }

    internal fun enc(s: String?): String {
        val raw = s ?: ""
        return URLEncoder.encode(raw, "UTF-8")
            .replace("+", "%20")
            .replace("%21", "!")
            .replace("%27", "'")
            .replace("%28", "(")
            .replace("%29", ")")
            .replace("%7E", "~")
    }

    internal fun dec(s: String?): String {
        val input = s ?: return ""
        if (!input.contains('%')) return input
        return runCatching {
            val out = ByteArrayOutputStream(input.length)
            var i = 0
            while (i < input.length) {
                val c = input[i]
                if (c == '%' && i + 2 < input.length) {
                    val hi = Character.digit(input[i + 1], 16)
                    val lo = Character.digit(input[i + 2], 16)
                    if (hi >= 0 && lo >= 0) {
                        out.write((hi shl 4) or lo)
                        i += 3
                        continue
                    }
                }
                val bytes = c.toString().toByteArray(Charsets.UTF_8)
                out.write(bytes)
                i++
            }
            String(out.toByteArray(), Charsets.UTF_8)
        }.getOrDefault(input)
    }

    internal fun isIpv4Addr(s: String): Boolean {
        val m = IPV4_REGEX.matchEntire(s.trim()) ?: return false
        return (1..4).all { (m.groupValues[it].toIntOrNull() ?: 256) <= 255 }
    }

    internal fun nonEmptyList(list: List<String>): List<String> =
        list.map { it.trim() }.filter { it.isNotEmpty() }

    private fun splitUrl(
        rawRest: String,
        allowNoPort: Boolean = false,
        allowMultiPort: Boolean = false
    ): SplitUrlResult? {
        var rest = rawRest
        var label = ""
        val hashIdx = rest.indexOf('#')
        if (hashIdx >= 0) {
            label = dec(rest.substring(hashIdx + 1))
            rest = rest.substring(0, hashIdx)
        }
        val query = LinkedHashMap<String, String>()
        val relays = mutableListOf<String>()
        val qIdx = rest.indexOf('?')
        if (qIdx >= 0) {
            val qPart = rest.substring(qIdx + 1)
            for (kv in qPart.split('&')) {
                val eq = kv.indexOf('=')
                if (eq > 0) {
                    val k = kv.substring(0, eq)
                    val v = dec(kv.substring(eq + 1))
                    if (k == "relay") {
                        if (v.isNotEmpty()) relays.add(v)
                    } else {
                        query[k] = v
                    }
                }
            }
            rest = rest.substring(0, qIdx)
        }
        rest = rest.removeSuffix("/")
        var user = ""
        val atIdx = rest.lastIndexOf('@')
        if (atIdx >= 0) {
            user = dec(rest.substring(0, atIdx))
            rest = rest.substring(atIdx + 1)
        }
        val portPattern = if (allowMultiPort) """(\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)""" else """(\d+)"""
        val v6Regex = Regex("""^\[([^\]]+)\]:$portPattern$""")
        val v4Regex = Regex("""^([^:]+):$portPattern$""")
        val m = v6Regex.matchEntire(rest) ?: v4Regex.matchEntire(rest)
        val host: String
        val port: String
        if (m != null) {
            host = m.groupValues[1]
            port = m.groupValues[2]
        } else if (allowNoPort && rest.isNotEmpty() && !rest.contains(':')) {
            host = rest
            port = ""
        } else {
            return null
        }
        return SplitUrlResult(
            label = label,
            query = query,
            relays = relays,
            user = user,
            host = host,
            port = port
        )
    }

    private fun applyTransport(
        node: ParsedNode,
        path: String?,
        host: String?,
        serviceName: String?,
        mode: String?,
        extra: String?,
        net: String?
    ): ParsedNode? {
        if (net.isNullOrEmpty() || net == "tcp" || net == "raw") {
            return node
        }
        return when (net) {
            "ws" -> node.copy(
                transport = "ws",
                wsPath = path.orEmpty(),
                wsHost = host.orEmpty()
            )
            "grpc" -> node.copy(
                transport = "grpc",
                grpcService = serviceName?.ifEmpty { null } ?: path.orEmpty()
            )
            "xhttp", "splithttp" -> {
                val withXhttp = node.copy(
                    transport = "xhttp",
                    xhttpPath = path.orEmpty(),
                    xhttpHost = host.orEmpty(),
                    xhttpMode = mode?.ifEmpty { null } ?: "auto",
                    xhttpExtra = extra.orEmpty()
                )
                splitIpPool(withXhttp)
            }
            else -> null
        }
    }

    private fun parseMpq(node: ParsedNode, q: Map<String, String>): ParsedNode {
        if (q["mpq"] != "1" && q["mpq-ports"].isNullOrEmpty() && q["mpq_ports"].isNullOrEmpty()) {
            return node
        }
        return node.copy(
            mpqEnable = true,
            mpqPorts = q["mpq-ports"] ?: q["mpq_ports"] ?: "",
            mpqToken = q["mpq-token"] ?: q["mpq_token"] ?: "",
            mpqObfs = q["mpq-obfs"] ?: q["mpq_obfs"] ?: "",
            mpqPaths = q["mpq-paths"] ?: q["mpq_paths"] ?: "",
            mpqServer = q["mpq-server"] ?: q["mpq_server"] ?: "",
            mpqSni = q["mpq-sni"] ?: q["mpq_sni"] ?: "",
            mpqCa = q["mpq-ca"] ?: q["mpq_ca"] ?: "",
            mpqInsecure = (q["mpq-insecure"] ?: q["mpq_insecure"]) == "1",
            mpqUpstream = q["mpq-upstream"] ?: q["mpq_upstream"] ?: "",
            mpqReorderMs = q["mpq-reorder-ms"] ?: q["mpq_reorder_ms"] ?: "",
            mpqCc = q["mpq-cc"] ?: q["mpq_cc"] ?: "",
            mpqAlpn = q["mpq-alpn"] ?: q["mpq_alpn"] ?: "",
            mpqDown = q["mpq-down"] ?: q["mpq_down"] ?: ""
        )
    }

    private fun splitIpPool(node: ParsedNode): ParsedNode {
        val raw = node.xhttpExtra
        if (raw.isBlank()) return node
        val ex = runCatching { JSONObject(raw) }.getOrNull() ?: return node
        if (!ex.has("ipPool")) return node
        val p = ex.opt("ipPool")
        val list: JSONArray? = when (p) {
            is JSONArray -> p
            is JSONObject -> p.optJSONArray("addresses")
            else -> null
        }
        if (list == null) return node
        val addrs = buildList {
            for (i in 0 until list.length()) {
                val item = list.optString(i, "").trim()
                if (item.isNotEmpty()) add(item)
            }
        }
        var updated = node.copy(xhttpIpPool = addrs.joinToString("\n"))
        if (p is JSONObject) {
            if (p.has("parallel") && !p.isNull("parallel")) updated = updated.copy(xhttpIpPoolParallel = p.opt("parallel")?.toString().orEmpty())
            if (p.has("hopSecs") && !p.isNull("hopSecs")) updated = updated.copy(xhttpIpPoolHop = p.opt("hopSecs")?.toString().orEmpty())
            if (p.has("probeMs") && !p.isNull("probeMs")) updated = updated.copy(xhttpIpPoolProbe = p.opt("probeMs")?.toString().orEmpty())
            if (p.has("probeTries") && !p.isNull("probeTries")) updated = updated.copy(xhttpIpPoolTries = p.opt("probeTries")?.toString().orEmpty())
            if (p.has("maxDraining") && !p.isNull("maxDraining")) updated = updated.copy(xhttpIpPoolDraining = p.opt("maxDraining")?.toString().orEmpty())
            if (p.has("drainSecs") && !p.isNull("drainSecs")) updated = updated.copy(xhttpIpPoolDrain = p.opt("drainSecs")?.toString().orEmpty())
            if (p.has("affinity") && !p.optBoolean("affinity", true)) {
                updated = updated.copy(xhttpIpPoolAffinity = "0")
            }
        }
        ex.remove("ipPool")
        return updated.copy(xhttpExtra = if (ex.length() > 0) ex.toString() else "")
    }

    internal fun effectiveExtra(node: ParsedNode): String {
        val ex = runCatching { JSONObject(node.xhttpExtra) }.getOrElse { JSONObject() }
        val addrs = node.xhttpIpPool.split(Regex("""[\s,]+""")).filter { it.isNotEmpty() }
        if (addrs.isNotEmpty()) {
            val pool = JSONObject()
            pool.put("addresses", JSONArray(addrs))
            val nums = listOf(
                node.xhttpIpPoolParallel to "parallel",
                node.xhttpIpPoolHop to "hopSecs",
                node.xhttpIpPoolProbe to "probeMs",
                node.xhttpIpPoolTries to "probeTries",
                node.xhttpIpPoolDraining to "maxDraining",
                node.xhttpIpPoolDrain to "drainSecs"
            )
            for ((rawVal, jsonKey) in nums) {
                val v = rawVal.toIntOrNull()
                if (v != null && v > 0) {
                    pool.put(jsonKey, v)
                }
            }
            if (node.xhttpIpPoolAffinity == "0") {
                pool.put("affinity", false)
            }
            ex.put("ipPool", pool)
        }
        return if (ex.length() > 0) ex.toString() else ""
    }

    internal fun splitTcpMeshHostPort(addr: String): HostPort? {
        val s = addr.trim()
        if (s.isEmpty() || s.any { it.isWhitespace() }) return null
        val m = Regex("""^\[([^\]]+)\]:([0-9]+)$""").matchEntire(s)
            ?: Regex("""^([^:]+):([0-9]+)$""").matchEntire(s)
            ?: return null
        val host = m.groupValues[1]
        val portInt = m.groupValues[2].toIntOrNull() ?: return null
        if (portInt !in 1..65535) return null
        if (s.startsWith('[') && !host.contains(':')) return null
        return HostPort(host, portInt.toString())
    }

    internal fun parseTcpMeshRelayEntry(raw: String): ParsedTcpMeshRelay {
        val parts = raw.trim().split('|')
        if (parts.size < 2 || parts.size > 7) {
            return ParsedTcpMeshRelay(error = "invalid relay format")
        }
        val addr = parts[0].trim()
        val sni = parts[1].trim()
        val hp = splitTcpMeshHostPort(addr)
            ?: return ParsedTcpMeshRelay(error = "invalid relay addr: $addr")
        if (sni.isEmpty() || sni.any { it.isWhitespace() }) {
            return ParsedTcpMeshRelay(error = "relay sni required")
        }
        val role = if (parts.size >= 3 && parts[2].trim().isNotEmpty()) parts[2].trim() else "both"
        if (role !in setOf("both", "up", "down")) {
            return ParsedTcpMeshRelay(error = "invalid relay role: $role")
        }
        var subUp: Int? = null
        if (parts.size >= 4 && parts[3].trim().isNotEmpty()) {
            val su = parts[3].trim()
            val v = su.toIntOrNull()
            if (!DIGITS_REGEX.matches(su) || v == null || v !in 0..16) {
                return ParsedTcpMeshRelay(error = "invalid subflows_up")
            }
            subUp = v
        }
        var subDown: Int? = null
        if (parts.size >= 5 && parts[4].trim().isNotEmpty()) {
            val sd = parts[4].trim()
            val v = sd.toIntOrNull()
            if (!DIGITS_REGEX.matches(sd) || v == null || v !in 0..16) {
                return ParsedTcpMeshRelay(error = "invalid subflows_down")
            }
            subDown = v
        }
        var group: Int? = null
        if (parts.size >= 6 && parts[5].trim().isNotEmpty()) {
            val rg = parts[5].trim()
            val v = rg.toIntOrNull()
            if (!DIGITS_REGEX.matches(rg) || v == null || v !in 1..255) {
                return ParsedTcpMeshRelay(error = "invalid relay_group")
            }
            group = v
        }
        val tag = if (parts.size >= 7) parts[6].trim() else ""
        return ParsedTcpMeshRelay(
            addr = addr,
            host = hp.host,
            port = hp.port,
            sni = sni,
            role = role,
            subflowsUp = subUp,
            subflowsDown = subDown,
            relayGroup = group,
            tag = tag
        )
    }

    private fun meshNumberValue(n: ParsedNode, key: String): String = when (key) {
        "hy2m_paths" -> n.hy2mPaths
        "hy2m_paths_up" -> n.hy2mPathsUp
        "hy2m_paths_down" -> n.hy2mPathsDown
        "hy2m_flow_paths" -> n.hy2mFlowPaths
        "hy2m_relay_ports" -> n.hy2mRelayPorts
        "hy2m_sessions" -> n.hy2mSessions
        "hy2m_hop_s" -> n.hy2mHopS
        "tcpmesh_sessions" -> n.tcpmeshSessions
        "tcpmesh_stream_win_mb" -> n.tcpmeshStreamWinMb
        "tcpmesh_session_mem_mb" -> n.tcpmeshSessionMemMb
        "tcpmesh_rotate_s" -> n.tcpmeshRotateS
        else -> ""
    }

    internal fun meshConfigError(n: ParsedNode): String? {
        val mode = n.hy2mTransportMode
        if (mode.isNotEmpty() && mode != "flow-path" && mode != "relay-stripe") {
            return "invalid transport_mode"
        }
        if (mode == "relay-stripe" && nonEmptyList(n.meshUp).isEmpty()) {
            return "relay-stripe requires explicit mesh_up"
        }
        for ((key, min, max) in MESH_NUMBERS) {
            val v = meshNumberValue(n, key)
            if (v.isEmpty()) continue
            val iv = v.toIntOrNull()
            if (!DIGITS_REGEX.matches(v) || iv == null || iv !in min..max) {
                return "$key out of range $min..$max"
            }
        }
        val up = n.hy2mPathsUp.toIntOrNull() ?: 0
        val down = n.hy2mPathsDown.toIntOrNull() ?: 0
        val total = n.hy2mPaths.toIntOrNull()
        val sum = up + down
        if (sum > 32 ||
            (total != null && (sum > total || ((up == 0 || down == 0) && sum > 0 && sum >= total))) ||
            (total == null && (up == 0 || down == 0) && sum == 32)
        ) {
            return "invalid direction quotas"
        }
        val cc = n.hy2Cc.ifEmpty { n.hy2UpCc }
        if (cc.isNotEmpty() && cc !in setOf("bbr", "cubic", "reno", "brutal")) {
            return "invalid mesh cc"
        }
        if (cc == "brutal") {
            val mbps = n.hy2UpMbps.toIntOrNull()
            if (!DIGITS_REGEX.matches(n.hy2UpMbps) || mbps == null || mbps !in 1..1_000_000) {
                return "brutal requires valid up_mbps"
            }
        }
        return null
    }

    internal fun hy2mLiteConfigError(n: ParsedNode): String? {
        if (n.password.isEmpty() || n.password.toByteArray(Charsets.UTF_8).size > 255) {
            return "invalid password"
        }
        val ups = nonEmptyList(n.meshUp)
        val downs = nonEmptyList(n.meshDown)
        if (downs.isNotEmpty() && ups.isEmpty()) {
            return "down requires up"
        }
        if (ups.isEmpty()) {
            val addr = n.address.trim()
            val port = n.port.trim()
            if (addr.isEmpty() || port.isEmpty()) return "address and port required"
            if (!isIpv4Addr(addr)) return "direct mode requires IPv4"
            val p = port.toIntOrNull()
            if (!DIGITS_REGEX.matches(port) || p == null || p !in 1..65535) return "invalid port"
        }
        for ((key, min, max) in HY2MLITE_NUMBERS) {
            val v = meshNumberValue(n, key)
            if (v.isEmpty()) continue
            val iv = v.toIntOrNull()
            if (!DIGITS_REGEX.matches(v) || iv == null || iv !in min..max) {
                return "$key out of range $min..$max"
            }
        }
        val up = n.hy2mPathsUp.toIntOrNull() ?: 0
        val down = n.hy2mPathsDown.toIntOrNull() ?: 0
        if (up + down > 32) return "paths_up + paths_down > 32"
        if (n.hy2mFec.isNotEmpty() && n.hy2mFec != "0" && n.hy2mFec != "1") {
            return "invalid fec"
        }
        return null
    }

    internal fun tcpmeshConfigError(n: ParsedNode): String? {
        if (n.password.isEmpty() || n.password.toByteArray(Charsets.UTF_8).size > 255) {
            return "invalid password"
        }
        val pbk = n.realityPublicKey.trim()
        if (!TCPMESH_PUBKEY_REGEX.matches(pbk)) return "invalid pbk"
        val sid = n.realityShortId.trim()
        if (sid.isNotEmpty() && (!TCPMESH_SID_REGEX.matches(sid) || sid.length % 2 != 0)) {
            return "invalid sid"
        }
        val fp = n.realityFingerprint.trim().lowercase()
        if (fp.isNotEmpty() && fp != "none" && fp !in TCPMESH_FP_KNOWN) {
            return "invalid fp"
        }
        val relays = nonEmptyList(n.tcpmeshRelays)
        var hasUp = false
        if (relays.isNotEmpty()) {
            if (relays.size > 16) return "too many relays"
            for (r in relays) {
                val parsed = parseTcpMeshRelayEntry(r)
                if (parsed.error != null) return parsed.error
                if (parsed.role == "up" || parsed.role == "both") hasUp = true
            }
        } else {
            val addr = n.address.trim()
            val port = n.port.trim()
            val sni = n.tlsSni.trim()
            if (addr.isEmpty() || port.isEmpty() || sni.isEmpty()) return "relays or address+port+sni required"
            val hp = (if (addr.contains(':')) "[$addr]" else addr) + ":$port"
            if (splitTcpMeshHostPort(hp) == null) return "invalid host:port"
            hasUp = true
        }
        if (!hasUp) return "at least one up/both relay required"
        for ((key, min, max) in TCPMESH_NUMBERS) {
            val v = meshNumberValue(n, key)
            if (v.isEmpty()) continue
            val iv = v.toIntOrNull()
            if (!DIGITS_REGEX.matches(v) || iv == null || iv !in min..max) {
                return "$key out of range $min..$max"
            }
        }
        val stripe = n.tcpmeshStripe.trim()
        if (stripe.isNotEmpty() && stripe !in setOf("auto", "off", "force")) return "invalid stripe"
        if (n.tcpmeshFailoverUp.isNotEmpty() && n.tcpmeshFailoverUp != "0" && n.tcpmeshFailoverUp != "1") {
            return "invalid failover_up"
        }
        if (n.tcpmeshLazyScale.isNotEmpty() && n.tcpmeshLazyScale != "0" && n.tcpmeshLazyScale != "1") {
            return "invalid lazy_scale"
        }
        return null
    }

    fun parseLink(rawLink: String): ParsedNode? {
        val link = unwrapMarkdownLinks(rawLink.trim())
        val m = SCHEME_REGEX.matchEntire(link) ?: return null
        val scheme = m.groupValues[1].lowercase()
        var rest = m.groupValues[2]

        if (scheme == "vmess") {
            val decoded = b64decode(rest) ?: return null
            val j = runCatching { JSONObject(decoded) }.getOrNull() ?: return null
            val add = j.optString("add", "")
            val port = if (j.has("port") && !j.isNull("port")) j.opt("port")?.toString().orEmpty() else ""
            val id = j.optString("id", "")
            val aid = if (j.has("aid") && !j.isNull("aid")) j.opt("aid")?.toString()?.ifBlank { "0" } ?: "0" else "0"
            val tlsEnabled = j.optString("tls", "") == "tls"
            var node = ParsedNode(
                type = "vmess",
                label = j.optString("ps", ""),
                address = add,
                port = port,
                uuid = id,
                vmessSecurity = j.optString("scy", "").ifBlank { "auto" },
                vmessAlterId = aid,
                tls = tlsEnabled,
                tlsSni = if (tlsEnabled) j.optString("sni", "") else "",
                tlsAlpn = if (tlsEnabled) j.optString("alpn", "") else ""
            )
            val extraObj = j.opt("extra")
            val extraStr = when (extraObj) {
                is JSONObject -> extraObj.toString()
                is String -> extraObj
                else -> ""
            }
            node = applyTransport(
                node = node,
                path = j.optString("path", ""),
                host = j.optString("host", ""),
                serviceName = j.optString("path", ""),
                mode = j.optString("mode", ""),
                extra = extraStr,
                net = j.optString("net", "")
            ) ?: return null
            return node
        }

        if (scheme == "ss") {
            var label = ""
            val hashIdx = rest.indexOf('#')
            if (hashIdx >= 0) {
                label = dec(rest.substring(hashIdx + 1))
                rest = rest.substring(0, hashIdx)
            }
            if (!rest.contains('@')) {
                rest = b64decode(rest.substringBefore('?')) ?: return null
            }
            val u = splitUrl(rest) ?: return null
            val cred = if (u.user.contains(':')) u.user else (b64decode(u.user) ?: "")
            val colon = cred.indexOf(':')
            if (colon <= 0) return null
            return ParsedNode(
                type = "shadowsocks",
                label = label,
                address = u.host,
                port = u.port,
                ssMethod = cred.substring(0, colon),
                password = cred.substring(colon + 1)
            )
        }

        val allowNoPort = scheme in setOf("hysteria2mesh", "hy2m", "hy2meshlite", "hy2mlite", "tcpmesh")
        val allowMultiPort = scheme == "hysteria2" || scheme == "hy2"
        val u = splitUrl(rest, allowNoPort = allowNoPort, allowMultiPort = allowMultiPort) ?: return null
        val q = u.query

        return when (scheme) {
            "vless" -> {
                val sec = q["security"] ?: ""
                val isTls = sec == "tls" || sec == "reality"
                val isReality = sec == "reality"
                val base = ParsedNode(
                    type = "vless",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    uuid = u.user,
                    tls = isTls,
                    tlsSni = if (isTls) q["sni"].orEmpty() else "",
                    tlsAlpn = if (isTls) q["alpn"].orEmpty() else "",
                    flow = if (isTls) q["flow"].orEmpty() else "",
                    reality = isReality,
                    realityPublicKey = if (isReality) q["pbk"].orEmpty() else "",
                    realityShortId = if (isReality) q["sid"].orEmpty() else "",
                    realityFingerprint = if (isReality) q["fp"].orEmpty() else ""
                )
                applyTransport(
                    node = base,
                    path = q["path"],
                    host = q["host"],
                    serviceName = q["serviceName"],
                    mode = q["mode"],
                    extra = q["extra"],
                    net = q["type"]
                )
            }

            "trojan" -> {
                val base = ParsedNode(
                    type = "trojan",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    password = u.user,
                    tls = q["security"] != "none",
                    tlsSni = q["sni"] ?: q["peer"] ?: "",
                    tlsAlpn = q["alpn"].orEmpty(),
                    tlsInsecure = q["allowInsecure"] == "1" || q["insecure"] == "1"
                )
                applyTransport(
                    node = base,
                    path = q["path"],
                    host = q["host"],
                    serviceName = q["serviceName"],
                    mode = q["mode"],
                    extra = q["extra"],
                    net = q["type"]
                )
            }

            "hysteria2mesh", "hy2m" -> {
                val upMbps = q["upmbps"] ?: q["up_mbps"] ?: ""
                val cc = q["cc"] ?: if (upMbps.isNotEmpty()) "brutal" else ""
                val hasObfs = !q["obfs"].isNullOrEmpty() || !q["obfs-password"].isNullOrEmpty()
                val node = ParsedNode(
                    type = "hysteria2mesh",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    password = u.user,
                    tlsSni = q["sni"].orEmpty(),
                    tlsAlpn = q["alpn"].orEmpty(),
                    tlsInsecure = q["insecure"] == "1" || q["allowInsecure"] == "1",
                    meshUp = q["up"]?.split(',')?.filter { it.isNotEmpty() } ?: emptyList(),
                    meshDown = q["down"]?.split(',')?.filter { it.isNotEmpty() } ?: emptyList(),
                    hy2ObfsType = if (hasObfs) (q["obfs"]?.ifEmpty { null } ?: "salamander") else "",
                    hy2ObfsPassword = if (hasObfs) q["obfs-password"].orEmpty() else "",
                    hy2mTransportMode = q["transport_mode"].orEmpty(),
                    hy2mRelayPorts = q["relay_ports"].orEmpty(),
                    hy2mSessions = q["sessions"].orEmpty(),
                    hy2mPaths = q["paths"].orEmpty(),
                    hy2mPathsUp = q["paths_up"] ?: q["pathsup"] ?: "",
                    hy2mPathsDown = q["paths_down"] ?: q["pathsdown"] ?: "",
                    hy2mFlowPaths = q["flow_paths"] ?: q["flowpaths"] ?: "",
                    hy2mHopS = q["hop_s"] ?: q["hops"] ?: "",
                    hy2UpMbps = upMbps,
                    hy2Cc = cc
                )
                if (meshConfigError(node) != null) null else node
            }

            "hy2meshlite", "hy2mlite" -> {
                val fecRaw = q["fec"].orEmpty()
                val fec = when (fecRaw.lowercase()) {
                    "0", "false" -> "0"
                    "1", "true" -> "1"
                    else -> fecRaw
                }
                val node = ParsedNode(
                    type = "hy2meshlite",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    password = u.user,
                    meshUp = q["up"]?.split(',')?.filter { it.isNotEmpty() } ?: emptyList(),
                    meshDown = q["down"]?.split(',')?.filter { it.isNotEmpty() } ?: emptyList(),
                    hy2mPaths = q["paths"].orEmpty(),
                    hy2mPathsUp = q["paths_up"] ?: q["pathsup"] ?: "",
                    hy2mPathsDown = q["paths_down"] ?: q["pathsdown"] ?: "",
                    hy2mSessions = q["sessions"].orEmpty(),
                    hy2mHopS = q["hop_s"] ?: q["hops"] ?: "",
                    hy2mFec = fec
                )
                if (hy2mLiteConfigError(node) != null) null else node
            }

            "tcpmesh" -> {
                val relays = if (u.relays.isNotEmpty()) {
                    u.relays
                } else {
                    q["relays"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
                }
                val failoverRaw = q["failover_up"].orEmpty()
                val failover = when (failoverRaw.lowercase()) {
                    "0", "false" -> "0"
                    "1", "true" -> "1"
                    else -> failoverRaw
                }
                val lazyRaw = q["lazy_scale"].orEmpty()
                val lazy = when (lazyRaw.lowercase()) {
                    "0", "false" -> "0"
                    "1", "true" -> "1"
                    else -> lazyRaw
                }
                val node = ParsedNode(
                    type = "tcpmesh",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    password = u.user,
                    realityPublicKey = q["pbk"].orEmpty(),
                    realityShortId = q["sid"].orEmpty(),
                    realityFingerprint = q["fp"].orEmpty(),
                    tlsSni = q["sni"].orEmpty(),
                    tlsAlpn = q["alpn"].orEmpty(),
                    tcpmeshRelays = relays,
                    tcpmeshSessions = q["sessions"].orEmpty(),
                    tcpmeshStripe = q["stripe"].orEmpty(),
                    tcpmeshFailoverUp = failover,
                    tcpmeshStreamWinMb = q["stream_win_mb"].orEmpty(),
                    tcpmeshSessionMemMb = q["session_mem_mb"].orEmpty(),
                    tcpmeshLazyScale = lazy,
                    tcpmeshRotateS = q["rotate_s"].orEmpty()
                )
                if (tcpmeshConfigError(node) != null) null else node
            }

            "hysteria2", "hy2" -> {
                val hasObfs = !q["obfs"].isNullOrEmpty() || !q["obfs-password"].isNullOrEmpty()
                var mainPort = u.port
                var hy2Ports = ""
                if (u.port.contains(',') || u.port.contains('-')) {
                    mainPort = LEADING_DIGITS_REGEX.find(u.port)?.value ?: u.port
                    hy2Ports = u.port
                }
                val qPorts = q["mport"] ?: q["ports"]
                if (!qPorts.isNullOrEmpty()) {
                    hy2Ports = qPorts
                }
                val upMbps = q["upmbps"] ?: q["up"] ?: ""
                val downMbps = q["downmbps"] ?: q["down"] ?: ""
                val cc = q["cc"] ?: if (upMbps.isNotEmpty()) "brutal" else ""
                val downCc = if (downMbps.isNotEmpty()) "brutal" else ""
                val base = ParsedNode(
                    type = "hysteria2",
                    label = u.label,
                    address = u.host,
                    port = mainPort,
                    password = u.user,
                    tlsSni = q["sni"].orEmpty(),
                    tlsAlpn = q["alpn"].orEmpty(),
                    tlsInsecure = q["insecure"] == "1" || q["allowInsecure"] == "1",
                    hy2ObfsType = if (hasObfs) (q["obfs"]?.ifEmpty { null } ?: "salamander") else "",
                    hy2ObfsPassword = if (hasObfs) q["obfs-password"].orEmpty() else "",
                    hy2Ports = hy2Ports,
                    hy2Conns = q["conns"].orEmpty(),
                    hy2UpMbps = upMbps,
                    hy2DownMbps = downMbps,
                    hy2Cc = cc,
                    hy2DownCc = downCc
                )
                parseMpq(base, q)
            }

            "tuic" -> {
                val colon = u.user.indexOf(':')
                val uuid = if (colon >= 0) u.user.substring(0, colon) else u.user
                val password = if (colon >= 0) u.user.substring(colon + 1) else ""
                val base = ParsedNode(
                    type = "tuic",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    uuid = uuid,
                    password = password,
                    tlsSni = q["sni"].orEmpty(),
                    tlsAlpn = q["alpn"].orEmpty(),
                    tuicCc = q["congestion_control"].orEmpty(),
                    tuicUdpRelayMode = q["udp_relay_mode"].orEmpty(),
                    tlsInsecure = q["allow_insecure"] == "1" || q["insecure"] == "1",
                    tuicConns = q["conns"].orEmpty(),
                    tuicPorts = q["mport"] ?: q["ports"] ?: ""
                )
                parseMpq(base, q)
            }

            "anytls" -> ParsedNode(
                type = "anytls",
                label = u.label,
                address = u.host,
                port = u.port,
                password = u.user,
                tlsSni = q["sni"].orEmpty(),
                tlsInsecure = q["insecure"] == "1"
            )

            "socks5", "socks", "http" -> {
                val colon = u.user.indexOf(':')
                val username = if (u.user.isEmpty()) "" else if (colon >= 0) u.user.substring(0, colon) else u.user
                val password = if (colon >= 0) u.user.substring(colon + 1) else ""
                ParsedNode(
                    type = if (scheme == "http") "http" else "socks",
                    label = u.label,
                    address = u.host,
                    port = u.port,
                    username = username,
                    password = password
                )
            }

            else -> null
        }
    }

    fun parseLinks(rawText: String): ParsedLinksResult {
        var text = rawText.trim()
        if (text.isNotEmpty() && !text.contains("://")) {
            text = b64decode(text).orEmpty()
        }
        val nodes = mutableListOf<ParsedNode>()
        val rawLinks = mutableListOf<String>()
        var bad = 0
        for (line in text.split(Regex("""[\r\n]+"""))) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) continue
            val n = parseLink(trimmed)
            val valid = n != null && (
                (n.address.isNotEmpty() && (n.port.isNotEmpty() || n.type in setOf("hysteria2mesh", "hy2meshlite", "tcpmesh"))) ||
                    (n.type == "tcpmesh" && nonEmptyList(n.tcpmeshRelays).isNotEmpty())
                )
            if (valid) {
                nodes.add(n!!)
                rawLinks.add(unwrapMarkdownLinks(trimmed))
            } else {
                bad++
            }
        }
        return ParsedLinksResult(nodes = nodes, rawLinks = rawLinks, bad = bad)
    }

    private fun hostPort(n: ParsedNode): String {
        val h = n.address
        val formattedHost = if (h.contains(':')) "[$h]" else h
        if (n.type in setOf("hysteria2mesh", "hy2meshlite", "tcpmesh") && n.port.isEmpty()) {
            return formattedHost
        }
        return "$formattedHost:${n.port}"
    }

    private fun buildQuery(pairs: List<Pair<String, String?>>): String {
        val out = pairs.mapNotNull { (k, v) ->
            if (!v.isNullOrEmpty()) "$k=${enc(v)}" else null
        }
        return if (out.isNotEmpty()) "?" + out.joinToString("&") else ""
    }

    private fun transportPairs(n: ParsedNode): List<Pair<String, String?>> {
        return when (n.transport.ifEmpty { "tcp" }) {
            "ws" -> listOf("type" to "ws", "path" to n.wsPath, "host" to n.wsHost)
            "grpc" -> listOf("type" to "grpc", "serviceName" to n.grpcService)
            "xhttp" -> listOf(
                "type" to "xhttp",
                "path" to n.xhttpPath,
                "host" to n.xhttpHost,
                "mode" to n.xhttpMode,
                "extra" to effectiveExtra(n)
            )
            else -> listOf("type" to "tcp")
        }
    }

    private fun mpqPairs(n: ParsedNode): List<Pair<String, String?>> {
        if (!n.mpqEnable) return emptyList()
        return listOf(
            "mpq" to "1",
            "mpq-ports" to n.mpqPorts,
            "mpq-token" to n.mpqToken,
            "mpq-obfs" to n.mpqObfs,
            "mpq-paths" to n.mpqPaths,
            "mpq-server" to n.mpqServer,
            "mpq-sni" to n.mpqSni,
            "mpq-ca" to n.mpqCa,
            "mpq-insecure" to if (n.mpqInsecure) "1" else "",
            "mpq-upstream" to n.mpqUpstream,
            "mpq-reorder-ms" to n.mpqReorderMs,
            "mpq-cc" to n.mpqCc,
            "mpq-alpn" to n.mpqAlpn,
            "mpq-down" to if (n.mpqDown.isNotEmpty() && n.mpqDown != "all") n.mpqDown else ""
        )
    }

    fun buildLink(node: ParsedNode): String? {
        val label = if (node.label.isNotEmpty()) "#${enc(node.label)}" else ""
        val hp = hostPort(node)
        val tls = node.tls
        val insecure = if (node.tlsInsecure) "1" else ""

        return when (node.type) {
            "vless" -> {
                val sec = if (!tls) "none" else if (node.reality) "reality" else "tls"
                val pv = mutableListOf<Pair<String, String?>>(
                    "encryption" to "none",
                    "security" to sec
                )
                if (tls) {
                    pv.add("sni" to node.tlsSni)
                    pv.add("alpn" to node.tlsAlpn)
                    pv.add("flow" to node.flow)
                }
                if (sec == "reality") {
                    pv.add("fp" to node.realityFingerprint.ifEmpty { "chrome" })
                    pv.add("pbk" to node.realityPublicKey)
                    pv.add("sid" to node.realityShortId)
                }
                "vless://${enc(node.uuid)}@$hp${buildQuery(pv + transportPairs(node))}$label"
            }

            "vmess" -> {
                val t = node.transport.ifEmpty { "tcp" }
                val j = JSONObject().apply {
                    put("v", "2")
                    put("ps", node.label)
                    put("add", node.address)
                    put("port", node.port)
                    put("id", node.uuid)
                    put("aid", node.vmessAlterId.ifEmpty { "0" })
                    put("scy", node.vmessSecurity.ifEmpty { "auto" })
                    put("net", t)
                    put("type", "none")
                    put("host", when (t) {
                        "ws" -> node.wsHost
                        "xhttp" -> node.xhttpHost
                        else -> ""
                    })
                    put("path", when (t) {
                        "ws" -> node.wsPath
                        "grpc" -> node.grpcService
                        "xhttp" -> node.xhttpPath
                        else -> ""
                    })
                    put("tls", if (tls) "tls" else "")
                    put("sni", if (tls) node.tlsSni else "")
                    put("alpn", if (tls) node.tlsAlpn else "")
                    if (t == "xhttp") {
                        put("mode", node.xhttpMode.ifEmpty { "auto" })
                        val vex = effectiveExtra(node)
                        if (vex.isNotEmpty()) put("extra", vex)
                    }
                }
                "vmess://${b64encode(j.toString())}"
            }

            "trojan" -> {
                val pairs = listOf(
                    "security" to if (tls) "tls" else "none",
                    "sni" to if (tls) node.tlsSni else "",
                    "alpn" to if (tls) node.tlsAlpn else "",
                    "allowInsecure" to if (tls) insecure else ""
                ) + transportPairs(node)
                "trojan://${enc(node.password)}@$hp${buildQuery(pairs)}$label"
            }

            "shadowsocks" -> {
                "ss://${enc(node.ssMethod)}:${enc(node.password)}@$hp$label"
            }

            "hysteria2mesh" -> {
                if (meshConfigError(node) != null) return null
                val ups = nonEmptyList(node.meshUp)
                val downs = nonEmptyList(node.meshDown)
                val obfs = if (node.hy2ObfsType == "salamander" || (node.hy2ObfsType.isEmpty() && node.hy2ObfsPassword.isNotEmpty())) "salamander" else ""
                val obfsPw = if (node.hy2ObfsType == "none") "" else node.hy2ObfsPassword
                val pairs = listOf(
                    "sni" to node.tlsSni,
                    "alpn" to node.tlsAlpn,
                    "insecure" to insecure,
                    "up" to ups.joinToString(","),
                    "down" to downs.joinToString(","),
                    "obfs" to obfs,
                    "obfs-password" to obfsPw,
                    "cc" to node.hy2Cc.ifEmpty { node.hy2UpCc },
                    "upmbps" to node.hy2UpMbps,
                    "paths" to node.hy2mPaths,
                    "paths_up" to node.hy2mPathsUp,
                    "paths_down" to node.hy2mPathsDown,
                    "flow_paths" to node.hy2mFlowPaths,
                    "transport_mode" to node.hy2mTransportMode,
                    "relay_ports" to node.hy2mRelayPorts,
                    "sessions" to node.hy2mSessions,
                    "hop_s" to node.hy2mHopS
                )
                "hysteria2mesh://${enc(node.password)}@$hp${buildQuery(pairs)}$label"
            }

            "hy2meshlite" -> {
                if (hy2mLiteConfigError(node) != null) return null
                val lups = nonEmptyList(node.meshUp)
                val ldowns = nonEmptyList(node.meshDown)
                val lhp = if (node.address.isEmpty() && lups.isNotEmpty()) {
                    val firstUp = lups.first().trim()
                    val colon = firstUp.lastIndexOf(':')
                    if (colon > 0) firstUp.substring(0, colon) else firstUp
                } else {
                    hp
                }
                val pairs = listOf(
                    "up" to lups.joinToString(","),
                    "down" to ldowns.joinToString(","),
                    "paths" to node.hy2mPaths,
                    "paths_up" to node.hy2mPathsUp,
                    "paths_down" to node.hy2mPathsDown,
                    "sessions" to node.hy2mSessions,
                    "hop_s" to node.hy2mHopS,
                    "fec" to if (node.hy2mFec == "0") "0" else ""
                )
                "hy2meshlite://${enc(node.password)}@$lhp${buildQuery(pairs)}$label"
            }

            "tcpmesh" -> {
                if (tcpmeshConfigError(node) != null) return null
                val trelays = nonEmptyList(node.tcpmeshRelays)
                val thp = if ((node.address.isEmpty() || node.port.isEmpty()) && trelays.isNotEmpty()) {
                    val firstR = parseTcpMeshRelayEntry(trelays.first())
                    if (firstR.error == null) firstR.addr else hp
                } else {
                    hp
                }
                val pairs = listOf(
                    "pbk" to node.realityPublicKey,
                    "sid" to node.realityShortId,
                    "fp" to node.realityFingerprint,
                    "sni" to node.tlsSni,
                    "alpn" to node.tlsAlpn,
                    "relays" to trelays.joinToString(","),
                    "sessions" to node.tcpmeshSessions,
                    "stripe" to node.tcpmeshStripe,
                    "failover_up" to node.tcpmeshFailoverUp,
                    "stream_win_mb" to node.tcpmeshStreamWinMb,
                    "session_mem_mb" to node.tcpmeshSessionMemMb,
                    "lazy_scale" to node.tcpmeshLazyScale,
                    "rotate_s" to node.tcpmeshRotateS
                )
                "tcpmesh://${enc(node.password)}@$thp${buildQuery(pairs)}$label"
            }

            "hysteria2" -> {
                val obfs = if (node.hy2ObfsType == "salamander" || (node.hy2ObfsType.isEmpty() && node.hy2ObfsPassword.isNotEmpty())) "salamander" else ""
                val obfsPw = if (node.hy2ObfsType == "none") "" else node.hy2ObfsPassword
                val pairs = listOf(
                    "sni" to node.tlsSni,
                    "alpn" to node.tlsAlpn,
                    "insecure" to insecure,
                    "obfs" to obfs,
                    "obfs-password" to obfsPw,
                    "upmbps" to node.hy2UpMbps,
                    "downmbps" to node.hy2DownMbps,
                    "cc" to if (node.hy2Cc == "cubic" || node.hy2Cc == "reno") node.hy2Cc else "",
                    "conns" to node.hy2Conns,
                    "mport" to node.hy2Ports
                ) + mpqPairs(node)
                "hysteria2://${enc(node.password)}@$hp${buildQuery(pairs)}$label"
            }

            "tuic" -> {
                val pairs = listOf(
                    "sni" to node.tlsSni,
                    "alpn" to node.tlsAlpn,
                    "congestion_control" to node.tuicCc,
                    "udp_relay_mode" to node.tuicUdpRelayMode,
                    "allow_insecure" to insecure,
                    "conns" to node.tuicConns,
                    "mport" to node.tuicPorts
                ) + mpqPairs(node)
                "tuic://${enc(node.uuid)}:${enc(node.password)}@$hp${buildQuery(pairs)}$label"
            }

            "anytls" -> {
                val pairs = listOf(
                    "sni" to node.tlsSni,
                    "insecure" to insecure
                )
                "anytls://${enc(node.password)}@$hp${buildQuery(pairs)}$label"
            }

            "socks", "http" -> {
                val auth = if (node.username.isNotEmpty()) {
                    enc(node.username) + (if (node.password.isNotEmpty()) ":${enc(node.password)}" else "") + "@"
                } else {
                    ""
                }
                val prefix = if (node.type == "socks") "socks5://" else "http://"
                "$prefix$auth$hp$label"
            }

            else -> null
        }
    }
}
