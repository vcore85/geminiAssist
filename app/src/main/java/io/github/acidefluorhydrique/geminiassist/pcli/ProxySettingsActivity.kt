package io.github.acidefluorhydrique.geminiassist.pcli

import android.app.Activity
import android.graphics.BitmapFactory
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.text.InputType
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.AppBarLayout
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.materialswitch.MaterialSwitch
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import io.github.acidefluorhydrique.geminiassist.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ProxySettingsActivity : AppCompatActivity() {

    private lateinit var store: PcliStore
    private lateinit var adapter: NodeAdapter

    private lateinit var statusDot: View
    private lateinit var tvStatus: TextView
    private lateinit var switchEnable: MaterialSwitch
    private lateinit var tvActiveNode: TextView
    private lateinit var tvEndpointInfo: TextView
    private lateinit var tvExitIp: TextView
    private lateinit var tvExitDelay: TextView
    private lateinit var tvExitMeta: TextView
    private lateinit var btnProbeExit: MaterialButton
    private lateinit var btnRestartCore: MaterialButton
    private lateinit var btnImport: MaterialButton
    private lateinit var btnScanQr: MaterialButton
    private lateinit var btnRefreshSub: MaterialButton
    private lateinit var btnConfig: MaterialButton
    private lateinit var btnLogs: MaterialButton
    private lateinit var tvNodesHeader: TextView
    private lateinit var btnTestAll: MaterialButton
    private lateinit var tvEmptyNodes: TextView
    private lateinit var rvNodes: RecyclerView

    private var suppressSwitchCallback = false
    private var proxyChanged = false

    private val qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents?.trim().orEmpty()
        if (contents.isNotEmpty()) {
            handleScannedQrContent(contents)
        }
    }

    private val qrImagePickerLauncher = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri == null) return@registerForActivityResult
        lifecycleScope.launch {
            val decoded = withContext(Dispatchers.IO) {
                runCatching {
                    contentResolver.openInputStream(uri)?.use { stream ->
                        val bmp = BitmapFactory.decodeStream(stream) ?: return@use null
                        try {
                            QrCodeHelper.decodeQrFromBitmap(bmp)
                        } finally {
                            bmp.recycle()
                        }
                    }
                }.getOrNull()
            }
            if (!decoded.isNullOrBlank()) {
                handleScannedQrContent(decoded.trim())
            } else {
                Toast.makeText(this@ProxySettingsActivity, "未在图片中识别到二维码", Toast.LENGTH_SHORT).show()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContentView(R.layout.activity_proxy_settings)
        store = PcliStore(this)

        applySystemBarInsets()

        val toolbar = findViewById<MaterialToolbar>(R.id.toolbar)
        toolbar.setNavigationOnClickListener { finishWithResult() }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                finishWithResult()
            }
        })

        statusDot = findViewById(R.id.statusDot)
        tvStatus = findViewById(R.id.tvStatus)
        switchEnable = findViewById(R.id.switchEnableProxy)
        tvActiveNode = findViewById(R.id.tvActiveNode)
        tvEndpointInfo = findViewById(R.id.tvEndpointInfo)
        tvExitIp = findViewById(R.id.tvExitIp)
        tvExitDelay = findViewById(R.id.tvExitDelay)
        tvExitMeta = findViewById(R.id.tvExitMeta)
        btnProbeExit = findViewById(R.id.btnProbeExit)
        btnRestartCore = findViewById(R.id.btnRestartCore)
        btnImport = findViewById(R.id.btnImport)
        btnScanQr = findViewById(R.id.btnScanQr)
        btnRefreshSub = findViewById(R.id.btnRefreshSub)
        btnConfig = findViewById(R.id.btnConfig)
        btnLogs = findViewById(R.id.btnLogs)
        tvNodesHeader = findViewById(R.id.tvNodesHeader)
        btnTestAll = findViewById(R.id.btnTestAll)
        tvEmptyNodes = findViewById(R.id.tvEmptyNodes)
        rvNodes = findViewById(R.id.rvNodes)

        adapter = NodeAdapter(
            onSelect = { profile -> onSelectNode(profile) },
            onDelete = { profile -> onDeleteNode(profile) }
        )
        rvNodes.layoutManager = LinearLayoutManager(this)
        rvNodes.adapter = adapter

        bindActions()
        refreshNodesUi()
        observeRuntime()
    }

    private fun applySystemBarInsets() {
        val appBar = findViewById<AppBarLayout>(R.id.appBar)
        val scrollContent = findViewById<View>(R.id.scrollContent)
        val initialBottom = scrollContent.paddingBottom
        val initialLeft = scrollContent.paddingLeft
        val initialRight = scrollContent.paddingRight
        val initialTop = scrollContent.paddingTop

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.rootProxySettings)) { _, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            appBar.setPadding(bars.left, bars.top, bars.right, 0)
            scrollContent.setPadding(
                initialLeft + bars.left,
                initialTop,
                initialRight + bars.right,
                initialBottom + bars.bottom
            )
            insets
        }
    }

    private fun finishWithResult() {
        setResult(if (proxyChanged) Activity.RESULT_OK else Activity.RESULT_CANCELED)
        finish()
    }

    private fun bindActions() {
        val settings = store.loadSettings()
        suppressSwitchCallback = true
        switchEnable.isChecked = settings.enabled
        suppressSwitchCallback = false

        switchEnable.setOnCheckedChangeListener { _, isChecked ->
            if (suppressSwitchCallback) return@setOnCheckedChangeListener
            val current = store.loadSettings()
            store.saveSettings(current.copy(enabled = isChecked))
            proxyChanged = true
            if (isChecked) {
                startOrRestartCore(autoProbe = true)
            } else {
                lifecycleScope.launch(Dispatchers.IO) {
                    PcliRuntime.stopSync(clearWebViewProxy = true)
                }
            }
        }

        btnRestartCore.setOnClickListener {
            val current = store.loadSettings()
            if (!current.enabled) {
                store.saveSettings(current.copy(enabled = true))
                suppressSwitchCallback = true
                switchEnable.isChecked = true
                suppressSwitchCallback = false
            }
            proxyChanged = true
            startOrRestartCore(autoProbe = true)
        }

        btnProbeExit.setOnClickListener { probeExitNow() }
        btnImport.setOnClickListener { showImportDialog() }
        btnScanQr.setOnClickListener { launchCameraQrScanner() }
        btnScanQr.setOnLongClickListener {
            qrImagePickerLauncher.launch("image/*")
            true
        }

        btnRefreshSub.setOnClickListener {
            val subUrl = store.loadSettings().subscriptionUrl
            if (subUrl.isBlank()) {
                Toast.makeText(this, "尚未保存订阅地址，请先导入订阅", Toast.LENGTH_SHORT).show()
                showImportDialog()
            } else {
                importSubscriptionUrl(subUrl, useProxy = PcliRuntime.isProxyActive())
            }
        }

        btnConfig.setOnClickListener { showConfigDialog() }
        btnLogs.setOnClickListener { showLogsDialog() }
        btnTestAll.setOnClickListener { testAllNodesTcpDelay() }
    }

    private fun launchCameraQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("扫描订阅链接或节点分享二维码")
            setBeepEnabled(false)
            setOrientationLocked(false)
        }
        qrScanLauncher.launch(options)
    }

    private fun handleScannedQrContent(content: String) {
        if (content.startsWith("http://", ignoreCase = true) ||
            content.startsWith("https://", ignoreCase = true)
        ) {
            Toast.makeText(this, "已识别订阅链接，正在拉取...", Toast.LENGTH_SHORT).show()
            importSubscriptionUrl(content, useProxy = PcliRuntime.isProxyActive())
            return
        }
        val summary = store.importFromText(content)
        refreshNodesUi()
        if (summary.importedCount > 0) {
            proxyChanged = true
            Toast.makeText(
                this,
                "扫码导入成功：${summary.importedCount} 个节点",
                Toast.LENGTH_SHORT
            ).show()
        } else {
            Toast.makeText(this, "二维码内容不是有效的订阅或节点链接", Toast.LENGTH_LONG).show()
        }
    }

    private fun observeRuntime() {
        lifecycleScope.launch {
            PcliRuntime.state.collectLatest { state ->
                renderRuntimeState(state)
            }
        }
    }

    private fun renderRuntimeState(state: PcliRuntimeState) {
        val settings = store.loadSettings()
        val active = store.getActiveProfile()
        val webViewSupport = if (WebViewProxyManager.isSupported()) "WebView 代理支持" else "WebView 不支持 PROXY_OVERRIDE"
        val coreVer = PcliBridge.version()

        when (state.status) {
            PcliStatus.RUNNING -> {
                statusDot.setBackgroundResource(android.R.drawable.presence_online)
                tvStatus.text = "运行中 (pcli $coreVer)"
            }
            PcliStatus.STARTING -> {
                statusDot.setBackgroundResource(android.R.drawable.presence_away)
                tvStatus.text = "正在启动 pcli..."
            }
            PcliStatus.ERROR -> {
                statusDot.setBackgroundResource(android.R.drawable.presence_busy)
                tvStatus.text = "错误：${state.errorMessage ?: "启动失败"}"
            }
            PcliStatus.STOPPED -> {
                statusDot.setBackgroundResource(android.R.drawable.presence_offline)
                tvStatus.text = "已停止 (pcli $coreVer)"
            }
        }

        tvActiveNode.text = "当前节点：${active?.name ?: "未选择"}"
        tvEndpointInfo.text = "本地代理：127.0.0.1:${settings.mixedPort} · API :${settings.apiPort} · $webViewSupport"

        val probe = state.exitProbe
        if (probe == null) {
            tvExitIp.text = "出口 IP：尚未探测"
            tvExitDelay.text = "-- ms"
            tvExitDelay.setTextColor(tvExitIp.currentTextColor)
            tvExitMeta.text = if (state.status == PcliStatus.RUNNING) {
                "点击下方“测延迟 & 出口 IP”获取当前代理出口信息"
            } else {
                "开启代理后可测试真实延迟与出口 IP"
            }
        } else {
            val flag = probe.flagEmoji?.let { "$it " }.orEmpty()
            val ipText = probe.exitIp ?: "获取失败"
            tvExitIp.text = "出口 IP：$flag$ipText"
            if (probe.delayMs >= 0) {
                tvExitDelay.text = "${probe.delayMs} ms"
                tvExitDelay.setTextColor(delayColor(probe.delayMs))
            } else {
                tvExitDelay.text = "超时"
                tvExitDelay.setTextColor(Color.parseColor("#E53935"))
            }
            val metaParts = listOfNotNull(
                probe.country?.takeIf { it.isNotBlank() },
                probe.isp?.takeIf { it.isNotBlank() },
                probe.error?.takeIf { it.isNotBlank() }
            )
            tvExitMeta.text = if (metaParts.isNotEmpty()) metaParts.joinToString(" · ") else "探测完成"
        }
    }

    private fun refreshNodesUi() {
        val profiles = store.loadProfiles()
        val activeId = store.getActiveProfile()?.id
        tvNodesHeader.text = "节点列表 (${profiles.size})"
        tvEmptyNodes.visibility = if (profiles.isEmpty()) View.VISIBLE else View.GONE
        adapter.submit(profiles, activeId)
        renderRuntimeState(PcliRuntime.state.value)
    }

    private fun onSelectNode(profile: ProxyProfile) {
        store.selectProfile(profile.id)
        proxyChanged = true
        refreshNodesUi()
        if (store.loadSettings().enabled) {
            startOrRestartCore(autoProbe = true)
        } else {
            Toast.makeText(this, "已选择节点：${profile.name}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun onDeleteNode(profile: ProxyProfile) {
        AlertDialog.Builder(this)
            .setTitle("删除节点")
            .setMessage("确定删除节点 “${profile.name}” 吗？")
            .setPositiveButton("删除") { _, _ ->
                val wasActive = store.getActiveProfile()?.id == profile.id
                store.deleteProfile(profile.id)
                refreshNodesUi()
                if (wasActive && PcliRuntime.isProxyActive()) {
                    proxyChanged = true
                    if (store.getActiveProfile() != null) {
                        startOrRestartCore(autoProbe = false)
                    } else {
                        lifecycleScope.launch(Dispatchers.IO) { PcliRuntime.stopSync(true) }
                    }
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun startOrRestartCore(autoProbe: Boolean) {
        lifecycleScope.launch {
            btnRestartCore.isEnabled = false
            btnProbeExit.isEnabled = false
            val ok = withContext(Dispatchers.IO) {
                PcliRuntime.startSync(this@ProxySettingsActivity)
            }
            btnRestartCore.isEnabled = true
            btnProbeExit.isEnabled = true
            if (!ok) {
                val err = PcliRuntime.state.value.errorMessage ?: "启动失败"
                Toast.makeText(this@ProxySettingsActivity, err, Toast.LENGTH_LONG).show()
            } else if (autoProbe) {
                probeExitNow()
            }
        }
    }

    private fun probeExitNow() {
        if (!PcliRuntime.isProxyActive()) {
            Toast.makeText(this, "请先启用 pcli 代理", Toast.LENGTH_SHORT).show()
            return
        }
        val settings = store.loadSettings()
        val activeId = store.getActiveProfile()?.id
        lifecycleScope.launch {
            btnProbeExit.isEnabled = false
            btnProbeExit.text = "探测中..."
            val client = ClashApiClient("127.0.0.1", settings.apiPort, settings.apiSecret)
            val result = NodeProbeHelper.probeConnectedExit(client, settings.mixedPort)
            PcliRuntime.updateExitProbe(result)
            if (activeId != null && result.delayMs >= 0) {
                store.updateDelay(activeId, result.delayMs)
                refreshNodesUi()
            }
            btnProbeExit.text = "测延迟 & 出口 IP"
            btnProbeExit.isEnabled = true
        }
    }

    private fun testAllNodesTcpDelay() {
        val profiles = store.loadProfiles()
        if (profiles.isEmpty()) {
            Toast.makeText(this, "暂无节点可测速", Toast.LENGTH_SHORT).show()
            return
        }
        lifecycleScope.launch {
            btnTestAll.isEnabled = false
            btnTestAll.text = "测速中..."
            coroutineScope {
                profiles.map { profile ->
                    async(Dispatchers.IO) {
                        val ms = NodeProbeHelper.testTcpDelay(profile)
                        store.updateDelay(profile.id, ms)
                    }
                }.awaitAll()
            }
            refreshNodesUi()
            btnTestAll.text = "全部测速"
            btnTestAll.isEnabled = true
            Toast.makeText(this@ProxySettingsActivity, "TCP 测速完成", Toast.LENGTH_SHORT).show()
        }
    }

    private fun showImportDialog() {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 12)
        }

        val radioGroup = RadioGroup(this).apply {
            orientation = RadioGroup.HORIZONTAL
        }
        val rbSub = RadioButton(this).apply {
            id = View.generateViewId()
            text = "订阅链接 (URL)"
            isChecked = true
        }
        val rbText = RadioButton(this).apply {
            id = View.generateViewId()
            text = "分享链接 / JSON"
        }
        radioGroup.addView(rbSub)
        radioGroup.addView(rbText)
        container.addView(radioGroup)

        val input = EditText(this).apply {
            hint = "https://example.com/sub"
            setText(store.loadSettings().subscriptionUrl)
            minLines = 3
            maxLines = 8
            isSingleLine = false
        }
        container.addView(input)

        val cbUseProxy = CheckBox(this).apply {
            text = "通过当前 pcli 代理拉取订阅"
            isChecked = PcliRuntime.isProxyActive()
            isEnabled = PcliRuntime.isProxyActive()
        }
        container.addView(cbUseProxy)

        radioGroup.setOnCheckedChangeListener { _, checkedId ->
            if (checkedId == rbSub.id) {
                input.hint = "https://example.com/sub"
                input.setText(store.loadSettings().subscriptionUrl)
                cbUseProxy.visibility = View.VISIBLE
            } else {
                input.hint = "粘贴 vless:// / hy2:// / trojan:// / ss:// / base64 或 pcli JSON"
                input.setText("")
                cbUseProxy.visibility = View.GONE
            }
        }

        AlertDialog.Builder(this)
            .setTitle("导入订阅 / 节点")
            .setView(container)
            .setPositiveButton("导入") { _, _ ->
                val raw = input.text?.toString().orEmpty().trim()
                if (raw.isEmpty()) {
                    Toast.makeText(this, "内容不能为空", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (rbSub.isChecked) {
                    importSubscriptionUrl(raw, useProxy = cbUseProxy.isChecked)
                } else {
                    val summary = store.importFromText(raw)
                    refreshNodesUi()
                    if (summary.importedCount > 0) {
                        proxyChanged = true
                        Toast.makeText(
                            this,
                            "已导入 ${summary.importedCount} 个节点" +
                                if (summary.failedCount > 0) "（忽略 ${summary.failedCount} 条无效）" else "",
                            Toast.LENGTH_SHORT
                        ).show()
                    } else {
                        Toast.makeText(this, "未解析出有效节点或配置", Toast.LENGTH_LONG).show()
                    }
                }
            }
            .setNeutralButton("相册二维码") { _, _ ->
                qrImagePickerLauncher.launch("image/*")
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun importSubscriptionUrl(url: String, useProxy: Boolean) {
        lifecycleScope.launch {
            btnImport.isEnabled = false
            btnRefreshSub.isEnabled = false
            btnScanQr.isEnabled = false
            val proxyPort = if (useProxy && PcliRuntime.isProxyActive()) PcliRuntime.activeMixedPort() else null
            val result = store.importFromSubscriptionUrl(url, useLocalProxyPort = proxyPort)
            btnImport.isEnabled = true
            btnRefreshSub.isEnabled = true
            btnScanQr.isEnabled = true
            result.onSuccess { summary ->
                proxyChanged = true
                refreshNodesUi()
                Toast.makeText(
                    this@ProxySettingsActivity,
                    "订阅更新成功，共 ${summary.importedCount} 个节点",
                    Toast.LENGTH_SHORT
                ).show()
            }.onFailure { err ->
                Toast.makeText(
                    this@ProxySettingsActivity,
                    "订阅拉取失败：${err.message ?: err.javaClass.simpleName}",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun showConfigDialog() {
        val settings = store.loadSettings()
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 24, 48, 12)
        }

        val tvMixed = TextView(this).apply { text = "本地 Mixed 代理端口 (HTTP + SOCKS5)" }
        val etMixed = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(settings.mixedPort.toString())
        }

        val tvApi = TextView(this).apply {
            text = "本地 Clash API 端口"
            setPadding(0, 16, 0, 0)
        }
        val etApi = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(settings.apiPort.toString())
        }

        val tvSecret = TextView(this).apply {
            text = "Clash API Secret（可留空）"
            setPadding(0, 16, 0, 0)
        }
        val etSecret = EditText(this).apply {
            setText(settings.apiSecret)
        }

        container.addView(tvMixed)
        container.addView(etMixed)
        container.addView(tvApi)
        container.addView(etApi)
        container.addView(tvSecret)
        container.addView(etSecret)

        AlertDialog.Builder(this)
            .setTitle("pcli 端口与配置")
            .setView(container)
            .setPositiveButton("保存") { _, _ ->
                val mixedPort = etMixed.text.toString().toIntOrNull()?.coerceIn(1024, 65535) ?: settings.mixedPort
                val apiPort = etApi.text.toString().toIntOrNull()?.coerceIn(1024, 65535) ?: settings.apiPort
                val secret = etSecret.text.toString().trim()
                store.saveSettings(
                    settings.copy(
                        mixedPort = mixedPort,
                        apiPort = apiPort,
                        apiSecret = secret
                    )
                )
                proxyChanged = true
                refreshNodesUi()
                if (PcliRuntime.isProxyActive()) {
                    startOrRestartCore(autoProbe = false)
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun showLogsDialog() {
        val logs = PcliBridge.recentLogs()
        val text = if (logs.isEmpty()) "暂无 pcli 内核日志" else logs.joinToString("\n")
        AlertDialog.Builder(this)
            .setTitle("pcli 内核日志")
            .setMessage(text)
            .setPositiveButton("关闭", null)
            .setNeutralButton("清空") { _, _ -> PcliBridge.clearLogs() }
            .show()
    }

    private fun delayColor(ms: Int): Int {
        return when {
            ms < 0 -> Color.parseColor("#E53935")
            ms < 180 -> Color.parseColor("#2E7D32")
            ms < 450 -> Color.parseColor("#EF6C00")
            else -> Color.parseColor("#C62828")
        }
    }

    private inner class NodeAdapter(
        private val onSelect: (ProxyProfile) -> Unit,
        private val onDelete: (ProxyProfile) -> Unit
    ) : RecyclerView.Adapter<NodeAdapter.VH>() {

        private var items: List<ProxyProfile> = emptyList()
        private var selectedId: String? = null

        fun submit(list: List<ProxyProfile>, activeId: String?) {
            items = list
            selectedId = activeId
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context).inflate(R.layout.item_proxy_node, parent, false)
            return VH(v)
        }

        override fun getItemCount(): Int = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            val isSelected = item.id == selectedId
            holder.tvProtocol.text = item.protocol.ifBlank { "PROXY" }.uppercase()
            holder.tvNodeName.text = item.name
            holder.tvNodeServer.text = item.serverSummary.ifBlank { item.protocol }

            val delay = item.lastDelayMs
            if (delay == null) {
                holder.tvNodeDelay.text = "--"
                holder.tvNodeDelay.setTextColor(holder.tvNodeServer.currentTextColor)
            } else if (delay < 0) {
                holder.tvNodeDelay.text = "超时"
                holder.tvNodeDelay.setTextColor(Color.parseColor("#E53935"))
            } else {
                holder.tvNodeDelay.text = "$delay ms"
                holder.tvNodeDelay.setTextColor(delayColor(delay))
            }

            holder.card.strokeColor = if (isSelected) {
                Color.parseColor("#2E7D32")
            } else {
                Color.parseColor("#33888888")
            }
            holder.card.strokeWidth = if (isSelected) 5 else 2

            holder.card.setOnClickListener { onSelect(item) }
            holder.btnDelete.setOnClickListener { onDelete(item) }
        }

        inner class VH(view: View) : RecyclerView.ViewHolder(view) {
            val card: MaterialCardView = view.findViewById(R.id.cardNode)
            val tvProtocol: TextView = view.findViewById(R.id.tvProtocol)
            val tvNodeName: TextView = view.findViewById(R.id.tvNodeName)
            val tvNodeServer: TextView = view.findViewById(R.id.tvNodeServer)
            val tvNodeDelay: TextView = view.findViewById(R.id.tvNodeDelay)
            val btnDelete: ImageButton = view.findViewById(R.id.btnDeleteNode)
        }
    }
}
