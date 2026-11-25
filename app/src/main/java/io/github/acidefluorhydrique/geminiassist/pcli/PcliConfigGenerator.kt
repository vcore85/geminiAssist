package io.github.acidefluorhydrique.geminiassist.pcli

import org.json.JSONArray
import org.json.JSONObject

object PcliConfigGenerator {

    private val RESERVED_TAGS = setOf("direct", "block", "main-out", "global", "reject", "wg", "proxy")
    private val DIGITS_REGEX = Regex("""^[0-9]+$""")

    fun generateForProfile(profile: ProxyProfile, settings: ProxySettings): String {
        if (profile.shareLink.isNotBlank()) {
            val parsed = ShareLinkCodec.parseLink(profile.shareLink)
            if (parsed != null) {
                return generateFromNode(parsed, settings)
            }
        }
        return patchRawJsonForMixed(profile.configJson, settings)
    }

    fun generateFromNode(node: ParsedNode, settings: ProxySettings): String {
        val nodeTag = resolveNodeTag(node.label)
        val nodeOutbound = buildNodeOutbound(node, nodeTag)

        val outbounds = JSONArray().apply {
            put(nodeOutbound)
            put(JSONObject().apply {
                put("name", "main-out")
                put("type", "selector")
                put("outbounds", JSONArray().apply {
                    put(nodeTag)
                    put("direct")
                })
                put("default", nodeTag)
            })
            put(JSONObject().apply {
                put("name", "direct")
                put("type", "direct")
            })
            put(JSONObject().apply {
                put("name", "block")
                put("type", "reject")
            })
        }

        val inbound = JSONObject().apply {
            put("mixed_listen", "127.0.0.1:${settings.mixedPort}")
            put("mixed_max_conn", 128)
            put("mixed_select_outbound", true)
        }

        val route = JSONObject().apply {
            put("final", "main-out")
        }

        val nodeDomains = collectNodeDomains(node)
        val dnsRules = JSONArray()
        if (nodeDomains.isNotEmpty()) {
            dnsRules.put(JSONObject().apply {
                put("domain", JSONArray(nodeDomains))
                put("server", "china")
            })
        }
        val dns = JSONObject().apply {
            put("mode", "forward")
            put("china", JSONArray(listOf("223.5.5.5", "119.29.29.29")))
            put("remote", JSONArray(listOf("8.8.8.8", "1.1.1.1")))
            put("rules", dnsRules)
            put("final", "remote")
            put("ipv6", false)
        }

        val experimental = JSONObject().apply {
            put("clash_api", JSONObject().apply {
                put("external_controller", "127.0.0.1:${settings.apiPort}")
                put("secret", settings.apiSecret)
                put("default_mode", "global")
            })
        }

        return JSONObject().apply {
            put("log", JSONObject().put("level", "info"))
            put("inbound", inbound)
            put("outbounds", outbounds)
            put("dns", dns)
            put("route", route)
            put("experimental", experimental)
        }.toString(2)
    }

    /**
     * Ensures a raw pcli JSON config has mixed_listen and clash_api configured
     * without requiring a TUN device.
     */
    private fun patchRawJsonForMixed(rawJson: String, settings: ProxySettings): String {
        return runCatching {
            val root = JSONObject(rawJson)
            val inbound = root.optJSONObject("inbound") ?: JSONObject().also { root.put("inbound", it) }
            inbound.put("mixed_listen", "127.0.0.1:${settings.mixedPort}")
            if (!inbound.has("mixed_max_conn")) {
                inbound.put("mixed_max_conn", 128)
            }
            inbound.put("mixed_select_outbound", true)

            val experimental = root.optJSONObject("experimental")
                ?: JSONObject().also { root.put("experimental", it) }
            val clashApi = experimental.optJSONObject("clash_api")
                ?: JSONObject().also { experimental.put("clash_api", it) }
            clashApi.put("external_controller", "127.0.0.1:${settings.apiPort}")
            clashApi.put("secret", settings.apiSecret)

            root.toString(2)
        }.getOrDefault(rawJson)
    }

    private fun collectNodeDomains(node: ParsedNode): List<String> {
        val domains = LinkedHashSet<String>()
        if (node.address.isNotBlank() && !ShareLinkCodec.isIpv4Addr(node.address) && !node.address.contains(':')) {
            domains.add(node.address.trim())
        }
        if (node.type == "tcpmesh") {
            for (raw in ShareLinkCodec.nonEmptyList(node.tcpmeshRelays)) {
                val parsed = ShareLinkCodec.parseTcpMeshRelayEntry(raw)
                if (parsed.error == null && parsed.host.isNotEmpty() &&
                    !ShareLinkCodec.isIpv4Addr(parsed.host) && !parsed.host.contains(':')
                ) {
                    domains.add(parsed.host)
                }
            }
        }
        return domains.toList()
    }

    private fun resolveNodeTag(label: String): String {
        val cleaned = buildString {
            for (ch in label.trim()) {
                if (length >= 64) break
                val code = ch.code
                if (code < 32 || code == 127) continue
                append(if (ch == '"' || ch == '\\' || ch == '/') '_' else ch)
            }
        }.trim()
        val lower = cleaned.lowercase()
        return if (cleaned.isNotEmpty() &&
            lower !in RESERVED_TAGS &&
            !lower.startsWith("node-") &&
            !lower.startsWith("group-")
        ) {
            cleaned
        } else {
            "node-main"
        }
    }

    private fun portsSafe(s: String): Boolean {
        if (s.isEmpty() || s.length > 128) return false
        var digit = false
        for (c in s) {
            when {
                c in '0'..'9' -> digit = true
                c == ',' || c == ':' || c == '-' || c == ' ' || c == '\t' -> Unit
                else -> return false
            }
        }
        return digit
    }

    private fun parseMbps(s: String): Number? {
        if (s.isBlank()) return null
        val d = s.trim().toDoubleOrNull() ?: return null
        if (d.isNaN() || d <= 0.0 || d > 1_000_000.0) return null
        val asLong = d.toLong()
        return if (d == asLong.toDouble()) asLong else d
    }

    private fun emitMpquic(n: ParsedNode, ob: JSONObject) {
        if (!portsSafe(n.mpqPorts) || n.mpqToken.isEmpty() || n.mpqToken.toByteArray(Charsets.UTF_8).size > 255) {
            return
        }
        if (n.mpqObfs.isNotEmpty()) {
            val len = n.mpqObfs.toByteArray(Charsets.UTF_8).size
            if (len !in 4..255) return
        }
        val mq = JSONObject().apply {
            put("ports", n.mpqPorts)
            put("token", n.mpqToken)
            if (n.mpqServer.isNotEmpty()) put("server", n.mpqServer)
            if (n.mpqSni.isNotEmpty()) put("sni", n.mpqSni)
            if (n.mpqCa.isNotEmpty()) put("ca", n.mpqCa)
            if (n.mpqUpstream.isNotEmpty()) put("upstream", n.mpqUpstream)
            if (n.mpqInsecure) put("insecure", true)
            n.mpqPaths.toIntOrNull()?.takeIf { it in 1..16 }?.let { put("paths", it) }
            if (n.mpqReorderMs.isNotEmpty()) {
                n.mpqReorderMs.toIntOrNull()?.takeIf { it in 0..1000 }?.let { put("reorder_ms", it) }
            }
            if (n.mpqCc in setOf("bbr", "bbr1", "cubic", "newreno")) put("cc", n.mpqCc)
            if (n.mpqAlpn in setOf("h3", "pcli-mpq/1")) put("alpn", n.mpqAlpn)
            if (n.mpqDown == "single") put("down", "single")
            if (n.mpqObfs.isNotEmpty()) {
                put("obfs", JSONObject().apply {
                    put("type", "salamander")
                    put("password", n.mpqObfs)
                })
            }
        }
        ob.put("mpquic", mq)
    }

    private fun emitQuicPool(n: ParsedNode, ob: JSONObject) {
        if (n.mpqEnable) {
            emitMpquic(n, ob)
            return
        }
        val conns = (n.hy2Conns.ifEmpty { n.tuicConns }).toIntOrNull() ?: 0
        if (conns in 2..8) {
            ob.put("conns", conns)
        }
        val ports = n.hy2Ports.ifEmpty { n.tuicPorts }
        if (ports.isNotEmpty() && portsSafe(ports)) {
            if (n.type == "hysteria2" && conns < 2) {
                ob.put("hop_ports", ports)
            } else {
                ob.put("ports", ports)
            }
        }
    }

    private fun buildNodeOutbound(n: ParsedNode, tag: String): JSONObject {
        val ob = JSONObject().apply {
            put("name", tag)
            if (n.address.isNotEmpty()) put("server", n.address)
            n.port.toIntOrNull()?.let { put("port", it) }
        }

        val t = n.type
        val tls = n.tls || t == "anytls"
        val quic = t == "hysteria2" || t == "hysteria2mesh" || t == "tuic"

        when (t) {
            "vless" -> {
                ob.put("type", "vless")
                ob.put("uuid", n.uuid)
                if (n.flow.isNotEmpty() && n.flow != "none") {
                    ob.put("flow", n.flow)
                }
            }

            "vmess" -> {
                ob.put("type", "vmess")
                ob.put("uuid", n.uuid)
                if (n.vmessSecurity.isNotEmpty()) ob.put("security", n.vmessSecurity)
                if (n.vmessAlterId.isNotEmpty() && n.vmessAlterId != "0") {
                    ob.put("alterId", n.vmessAlterId)
                }
            }

            "trojan" -> {
                ob.put("type", "trojan")
                ob.put("password", n.password)
            }

            "shadowsocks" -> {
                ob.put("type", "ss2022")
                ob.put("method", n.ssMethod)
                ob.put("password", n.password)
            }

            "hysteria2" -> {
                ob.put("type", "hysteria2")
                ob.put("password", n.password)
                val ot = n.hy2ObfsType
                val op = n.hy2ObfsPassword
                if (ot == "salamander" || (ot.isEmpty() && op.isNotEmpty())) {
                    val len = op.toByteArray(Charsets.UTF_8).size
                    if (len in 4..512) {
                        ob.put("obfs", JSONObject().apply {
                            put("type", "salamander")
                            put("password", op)
                        })
                    }
                }
                val upCc = n.hy2UpCc.ifEmpty { n.hy2Cc }
                val up = parseMbps(n.hy2UpMbps)
                when {
                    upCc == "brutal" && up != null -> {
                        ob.put("cc", "brutal")
                        ob.put("up_mbps", up)
                    }
                    upCc in setOf("bbr", "cubic", "reno") -> ob.put("cc", upCc)
                    up != null -> ob.put("up_mbps", up)
                }
                val downCc = n.hy2DownCc
                val down = parseMbps(n.hy2DownMbps)
                if ((downCc == "brutal" || downCc.isEmpty()) && down != null) {
                    ob.put("down_mbps", down)
                }
                emitQuicPool(n, ob)
            }

            "hysteria2mesh" -> {
                ob.put("type", "hysteria2mesh")
                ob.put("password", n.password)
                ob.remove("server")
                ob.remove("port")
                val mode = n.hy2mTransportMode
                if (mode == "flow-path" || mode == "relay-stripe") {
                    ob.put("transport_mode", mode)
                }
                val boot = if (n.address.isNotEmpty() && n.port.isNotEmpty()) "${n.address}:${n.port}" else ""
                val upList = mutableListOf<String>()
                if (boot.isNotEmpty() && mode != "relay-stripe") {
                    upList.add(boot)
                }
                for (item in ShareLinkCodec.nonEmptyList(n.meshUp)) {
                    if (mode == "relay-stripe" || item != boot) {
                        upList.add(item)
                    }
                }
                if (upList.isNotEmpty()) ob.put("up", JSONArray(upList))
                val downList = ShareLinkCodec.nonEmptyList(n.meshDown)
                if (downList.isNotEmpty()) ob.put("down", JSONArray(downList))
                putIntInRange(ob, "paths", n.hy2mPaths, 1, 32)
                putIntInRange(ob, "paths_up", n.hy2mPathsUp, 0, 32)
                putIntInRange(ob, "paths_down", n.hy2mPathsDown, 0, 32)
                putIntInRange(ob, "flow_paths", n.hy2mFlowPaths, 1, 8)
                putIntInRange(ob, "relay_ports", n.hy2mRelayPorts, 1, 4)
                putIntInRange(ob, "sessions", n.hy2mSessions, 1, 8)
                putIntInRange(ob, "hop_s", n.hy2mHopS, 0, 3600)
                val ot = n.hy2ObfsType
                val op = n.hy2ObfsPassword
                if (ot == "salamander" || (ot.isEmpty() && op.isNotEmpty())) {
                    val len = op.toByteArray(Charsets.UTF_8).size
                    if (len in 4..255) {
                        ob.put("obfs", JSONObject().apply {
                            put("type", "salamander")
                            put("password", op)
                        })
                    }
                }
                val upCc = n.hy2Cc.ifEmpty { n.hy2UpCc }
                val mbps = parseMbps(n.hy2UpMbps)
                when {
                    upCc == "brutal" && mbps != null -> {
                        ob.put("cc", "brutal")
                        ob.put("up_mbps", mbps)
                    }
                    upCc in setOf("bbr", "cubic", "reno") -> ob.put("cc", upCc)
                    mbps != null -> ob.put("up_mbps", mbps)
                }
                if (n.tlsAlpn == "pcli-hy2m/1") {
                    ob.put("alpn", "pcli-hy2m/1")
                }
            }

            "hy2meshlite" -> {
                ob.put("type", "hy2meshlite")
                ob.put("password", n.password)
                val upList = ShareLinkCodec.nonEmptyList(n.meshUp)
                val downList = ShareLinkCodec.nonEmptyList(n.meshDown)
                if (upList.isNotEmpty()) {
                    ob.remove("server")
                    ob.remove("port")
                    ob.put("up", JSONArray(upList))
                    if (downList.isNotEmpty()) ob.put("down", JSONArray(downList))
                } else {
                    ob.put("server", n.address)
                    n.port.toIntOrNull()?.let { ob.put("port", it) }
                }
                putIntInRange(ob, "paths", n.hy2mPaths, 1, 32)
                putIntInRange(ob, "paths_up", n.hy2mPathsUp, 0, 32)
                putIntInRange(ob, "paths_down", n.hy2mPathsDown, 0, 32)
                putIntInRange(ob, "sessions", n.hy2mSessions, 1, 8)
                putIntInRange(ob, "hop_s", n.hy2mHopS, 0, 3600)
                if (n.hy2mFec == "0") ob.put("fec", false)
                else if (n.hy2mFec == "1") ob.put("fec", true)
                return ob
            }

            "tcpmesh" -> {
                ob.put("type", "tcpmesh")
                ob.remove("server")
                ob.remove("port")
                ob.put("auth", n.password)
                ob.put("reality", JSONObject().apply {
                    put("public_key", n.realityPublicKey.trim())
                    if (n.realityShortId.trim().isNotEmpty()) {
                        put("short_id", n.realityShortId.trim())
                    }
                })
                val fp = n.realityFingerprint.trim().lowercase()
                if (fp.isNotEmpty() && fp != "none") {
                    ob.put("fingerprint", fp)
                }
                val relaysArray = JSONArray()
                val rawRelays = ShareLinkCodec.nonEmptyList(n.tcpmeshRelays)
                if (rawRelays.isNotEmpty()) {
                    for (raw in rawRelays) {
                        val r = ShareLinkCodec.parseTcpMeshRelayEntry(raw)
                        if (r.error == null) {
                            relaysArray.put(JSONObject().apply {
                                put("addr", r.addr)
                                put("sni", r.sni)
                                put("role", r.role)
                                r.subflowsUp?.let { put("subflows_up", it) }
                                r.subflowsDown?.let { put("subflows_down", it) }
                                r.relayGroup?.let { put("relay_group", it) }
                                if (r.tag.isNotEmpty()) put("tag", r.tag)
                            })
                        }
                    }
                } else if (n.address.isNotEmpty() && n.port.isNotEmpty() && n.tlsSni.isNotEmpty()) {
                    val hp = (if (n.address.contains(':')) "[${n.address}]" else n.address) + ":${n.port}"
                    relaysArray.put(JSONObject().apply {
                        put("addr", hp)
                        put("sni", n.tlsSni)
                        put("role", "both")
                    })
                }
                ob.put("relays", relaysArray)
                putIntInRange(ob, "sessions", n.tcpmeshSessions, 1, 8)
                putIntInRange(ob, "stream_win_mb", n.tcpmeshStreamWinMb, 1, 64)
                putIntInRange(ob, "session_mem_mb", n.tcpmeshSessionMemMb, 4, 256)
                putIntInRange(ob, "rotate_s", n.tcpmeshRotateS, 0, 86400)
                if (n.tcpmeshStripe in setOf("auto", "off", "force")) ob.put("stripe", n.tcpmeshStripe)
                if (n.tcpmeshFailoverUp == "0") ob.put("failover_up", false)
                else if (n.tcpmeshFailoverUp == "1") ob.put("failover_up", true)
                if (n.tcpmeshLazyScale == "0") ob.put("lazy_scale", false)
                else if (n.tcpmeshLazyScale == "1") ob.put("lazy_scale", true)
                if (n.tlsAlpn.trim().isNotEmpty()) ob.put("alpn", n.tlsAlpn.trim())
                return ob
            }

            "tuic" -> {
                ob.put("type", "tuic")
                ob.put("uuid", n.uuid)
                ob.put("password", n.password)
                if (n.tuicCc.isNotEmpty()) ob.put("cc", n.tuicCc)
                if (n.tuicUdpRelayMode.isNotEmpty()) ob.put("udp_relay_mode", n.tuicUdpRelayMode)
                emitQuicPool(n, ob)
            }

            "anytls" -> {
                ob.put("type", "anytls")
                ob.put("password", n.password)
            }

            "socks", "http" -> {
                ob.put("type", if (t == "socks") "socks5" else "http")
                if (n.username.isNotEmpty()) ob.put("username", n.username)
                if (n.password.isNotEmpty()) ob.put("password", n.password)
            }
        }

        var sni = n.tlsSni
        if ((tls || quic) && sni.isEmpty() && n.address.isNotEmpty() && !ShareLinkCodec.isIpv4Addr(n.address)) {
            sni = n.address
        }
        if (tls) ob.put("tls", true)
        if ((tls || quic) && sni.isNotEmpty()) ob.put("sni", sni)
        if ((tls || quic) && n.tlsInsecure) ob.put("insecure", true)
        if ((tls || quic) && n.tlsAlpn.isNotEmpty() && t != "hysteria2mesh") {
            ob.put("alpn", n.tlsAlpn)
        }
        if (t == "vless" && n.reality) {
            ob.put("tls", true)
            ob.remove("insecure")
            ob.put("reality", JSONObject().apply {
                put("public_key", n.realityPublicKey)
                if (n.realityShortId.isNotEmpty()) put("short_id", n.realityShortId)
                if (n.realityFingerprint.isNotEmpty()) put("fingerprint", n.realityFingerprint)
            })
        }

        val net = n.transport.ifEmpty { "tcp" }
        if (net != "tcp" && (t == "vless" || t == "vmess" || t == "trojan")) {
            ob.put("network", net)
            when (net) {
                "ws" -> {
                    if (n.wsPath.isNotEmpty()) ob.put("path", n.wsPath)
                    if (n.wsHost.isNotEmpty()) ob.put("host", n.wsHost)
                }
                "grpc" -> {
                    if (n.grpcService.isNotEmpty()) ob.put("path", n.grpcService)
                }
                "xhttp" -> {
                    if (n.xhttpPath.isNotEmpty()) ob.put("path", n.xhttpPath)
                    val xh = n.xhttpHost.ifEmpty { sni }.ifEmpty { n.address }
                    if (xh.isNotEmpty()) ob.put("host", xh)
                    if (n.xhttpMode.isNotEmpty() && n.xhttpMode != "auto") {
                        ob.put("mode", n.xhttpMode)
                    }
                    val extraJson = ShareLinkCodec.effectiveExtra(n)
                    if (extraJson.isNotEmpty()) {
                        runCatching { JSONObject(extraJson) }.getOrNull()?.let {
                            ob.put("extra", it)
                        }
                    }
                }
            }
        }

        return ob
    }

    private fun putIntInRange(ob: JSONObject, key: String, raw: String, min: Int, max: Int) {
        if (raw.isEmpty() || !DIGITS_REGEX.matches(raw)) return
        val v = raw.toIntOrNull() ?: return
        if (v in min..max) {
            ob.put(key, v)
        }
    }
}
