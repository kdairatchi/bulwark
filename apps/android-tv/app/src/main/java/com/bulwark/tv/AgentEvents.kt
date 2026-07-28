package com.bulwark.tv

import com.bulwark.deviceapi.DeviceEvent
import com.bulwark.deviceapi.EventBatcher

/** Process-wide event queue flushed to the control plane on each agent tick. */
object AgentEvents {
    val batcher = EventBatcher()

    fun dnsBlocked(host: String) = batcher.add(DeviceEvent.dnsBlocked(host))

    fun isolationChanged(isolated: Boolean) = batcher.add(DeviceEvent.isolationChanged(isolated))

    fun finding(subject: String, reason: String, level: String) =
        batcher.add(DeviceEvent.findingRaised(subject, reason, level))

    fun dnsGuardPending(detail: String = "VPN permission required for DNS Guard") =
        batcher.add(DeviceEvent.dnsGuardPending(detail))
}
