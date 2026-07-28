package com.bulwark.tv

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.tv.material3.ClickableSurfaceDefaults
import androidx.tv.material3.ExperimentalTvMaterial3Api
import androidx.tv.material3.Surface
import androidx.tv.material3.Text
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BulwarkTvApp()
        }
    }
}

private val Bg = Color(0xFF0B1220)
private val Card = Color(0xFF151D2E)
private val Accent = Color(0xFFF59E0B)
private val Muted = Color(0xFF94A3B8)
private val Text = Color(0xFFF8FAFC)

@OptIn(ExperimentalTvMaterial3Api::class)
@Composable
fun BulwarkTvApp() {
    val context = LocalContext.current
    val agent = remember { DeviceAgentService(context) }
    val blocklist = remember { BlocklistStore(context) }
    val scope = rememberCoroutineScope()

    var identity by remember { mutableStateOf(IdentityStore(context).load()) }
    var baseUrl by remember { mutableStateOf(identity?.baseUrl ?: "http://10.0.2.2:8787") }
    var pairingCode by remember { mutableStateOf("") }
    var statusMessage by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var dnsRunning by remember { mutableStateOf(DnsGuardVpnService.isRunning) }

    val vpnPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            DnsGuardVpnService.start(context)
            dnsRunning = true
            statusMessage = "DNS Guard started (${blocklist.size()} blocked domains)"
        } else {
            statusMessage = "DNS Guard permission denied"
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(Bg)
            .padding(48.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text(
            text = "Bulwark",
            color = Accent,
            fontSize = 42.sp,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "Android TV security agent",
            color = Muted,
            fontSize = 18.sp,
        )
        Spacer(Modifier.height(28.dp))

        if (identity == null) {
            Text(text = "Enroll this TV", color = Text, fontSize = 28.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            Text(
                text = "Enter a pairing code from your Bulwark control plane (npm run cloud:dev).",
                color = Muted,
                fontSize = 16.sp,
            )
            Spacer(Modifier.height(20.dp))
            LabeledField("Control plane URL", baseUrl) { baseUrl = it }
            Spacer(Modifier.height(12.dp))
            LabeledField("Pairing code", pairingCode) { pairingCode = it.uppercase() }
            Spacer(Modifier.height(20.dp))
            Row {
                FocusButton("Enroll device", enabled = !busy && pairingCode.isNotBlank()) {
                    busy = true
                    statusMessage = "Enrolling…"
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            agent.enroll(pairingCode, baseUrl, Build.MODEL)
                        }
                        busy = false
                        result.fold(
                            onSuccess = {
                                identity = it
                                statusMessage = "Enrolled as ${it.deviceId}"
                                (context.applicationContext as? BulwarkApp)?.scheduleAgentWork()
                            },
                            onFailure = {
                                statusMessage = "Enroll failed: ${it.message}"
                            },
                        )
                    }
                }
            }
        } else {
            Text(text = "Device status", color = Text, fontSize = 28.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(12.dp))
            StatusCard(
                deviceId = identity!!.deviceId,
                baseUrl = identity!!.baseUrl,
                model = "${Build.MANUFACTURER} ${Build.MODEL}",
                enrolledAt = identity!!.enrolledAt,
                dnsRunning = dnsRunning,
                blocklistSize = blocklist.size(),
                dnsStats = DnsGuardVpnService.trafficSummary(),
            )
            Spacer(Modifier.height(20.dp))
            Row {
                FocusButton("Poll now", enabled = !busy) {
                    busy = true
                    statusMessage = "Polling…"
                    scope.launch {
                        val result = withContext(Dispatchers.IO) { agent.tick() }
                        busy = false
                        result.fold(
                            onSuccess = {
                                statusMessage =
                                    "Tick ok — processed=${it.processed} rejected=${it.rejected} last=${it.lastType ?: "—"}"
                            },
                            onFailure = { statusMessage = "Tick failed: ${it.message}" },
                        )
                    }
                }
                Spacer(Modifier.width(16.dp))
                FocusButton("Scan apps", enabled = !busy) {
                    busy = true
                    scope.launch {
                        val inv = withContext(Dispatchers.IO) { agent.collectInventory() }
                        busy = false
                        statusMessage =
                            "Apps ${inv["count"]} · sideloaded ${inv["sideloadedCount"]} · posture ${inv["postureScore"]} · findings ${(inv["_findings"] as? List<*>)?.size ?: 0}"
                    }
                }
                Spacer(Modifier.width(16.dp))
                FocusButton(if (dnsRunning) "Stop DNS Guard" else "Start DNS Guard", enabled = !busy) {
                    if (dnsRunning) {
                        DnsGuardVpnService.stop(context)
                        dnsRunning = false
                        statusMessage = "DNS Guard stopped"
                    } else {
                        if (blocklist.size() == 0) blocklist.addAll(BlocklistStore.STARTER)
                        val prepare = DnsGuardVpnService.prepareIntent(context)
                        if (prepare != null) {
                            vpnPermission.launch(prepare)
                        } else {
                            DnsGuardVpnService.start(context)
                            dnsRunning = true
                            statusMessage = "DNS Guard started (${blocklist.size()} domains)"
                        }
                    }
                }
                Spacer(Modifier.width(16.dp))
                FocusButton("Unenroll", enabled = !busy) {
                    agent.unenroll()
                    identity = null
                    statusMessage = "Unenrolled"
                }
            }
        }

        if (statusMessage.isNotBlank()) {
            Spacer(Modifier.height(24.dp))
            Text(text = statusMessage, color = Accent, fontSize = 16.sp)
        }
    }
}

@Composable
private fun LabeledField(label: String, value: String, onChange: (String) -> Unit) {
    Column(Modifier.fillMaxWidth(0.7f)) {
        Text(text = label, color = Muted, fontSize = 14.sp)
        Spacer(Modifier.height(6.dp))
        BasicTextField(
            value = value,
            onValueChange = onChange,
            textStyle = TextStyle(color = Text, fontSize = 20.sp),
            cursorBrush = SolidColor(Accent),
            modifier = Modifier
                .fillMaxWidth()
                .background(Card)
                .padding(horizontal = 16.dp, vertical = 14.dp),
            singleLine = true,
        )
    }
}

@Composable
private fun StatusCard(
    deviceId: String,
    baseUrl: String,
    model: String,
    enrolledAt: String,
    dnsRunning: Boolean,
    blocklistSize: Int,
    dnsStats: Map<String, Any?>,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth(0.85f)
            .background(Card)
            .padding(20.dp),
    ) {
        Text(text = "Device ID: $deviceId", color = Text, fontSize = 18.sp)
        Text(text = "Control plane: $baseUrl", color = Muted, fontSize = 16.sp)
        Text(text = "Hardware: $model", color = Muted, fontSize = 16.sp)
        Text(text = "Enrolled: $enrolledAt", color = Muted, fontSize = 16.sp)
        Text(
            text = "DNS Guard: ${if (dnsRunning) "ON" else "OFF"} · blocklist $blocklistSize · queries ${dnsStats["queries"]} · blocks ${dnsStats["blocks"]}",
            color = if (dnsRunning) Accent else Muted,
            fontSize = 16.sp,
        )
        val last = dnsStats["lastBlockedHost"] as? String
        if (!last.isNullOrBlank()) {
            Text(text = "Last blocked: $last", color = Accent, fontSize = 14.sp)
        }
    }
}

@OptIn(ExperimentalTvMaterial3Api::class)
@Composable
private fun FocusButton(label: String, enabled: Boolean, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        enabled = enabled,
        colors = ClickableSurfaceDefaults.colors(
            containerColor = Accent,
            contentColor = Color.Black,
            focusedContainerColor = Color(0xFFFBBF24),
            disabledContainerColor = Color(0xFF334155),
        ),
        modifier = Modifier.padding(end = 4.dp),
    ) {
        Text(
            text = label,
            modifier = Modifier.padding(horizontal = 22.dp, vertical = 14.dp),
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
            color = Color.Black,
        )
    }
}
