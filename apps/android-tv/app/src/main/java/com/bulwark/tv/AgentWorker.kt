package com.bulwark.tv

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.bulwark.deviceapi.DeviceApiClient

class AgentWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val store = IdentityStore(applicationContext)
        if (store.load() == null) return Result.success()
        val agent = DeviceAgentService(store, applicationContext.packageManager)
        return agent.tick().fold(
            onSuccess = { report ->
                // Submit sideload findings collected during inventory.
                val identity = store.load()
                if (identity != null) {
                    runCatching {
                        val inventory = agent.collectInventory()
                        @Suppress("UNCHECKED_CAST")
                        val findings = inventory["_findings"] as? List<Map<String, Any?>> ?: emptyList()
                        if (findings.isNotEmpty()) {
                            DeviceApiClient(identity.baseUrl).submitFindings(identity, findings)
                        }
                    }
                }
                Result.success()
            },
            onFailure = { Result.retry() },
        )
    }

    companion object {
        const val UNIQUE_NAME = "bulwark-device-agent"
    }
}
