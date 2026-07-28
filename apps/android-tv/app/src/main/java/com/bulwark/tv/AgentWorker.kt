package com.bulwark.tv

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

class AgentWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val store = IdentityStore(applicationContext)
        if (store.load() == null) return Result.success()
        val agent = DeviceAgentService(applicationContext, store)
        return agent.tick().fold(
            onSuccess = { Result.success() },
            onFailure = { Result.retry() },
        )
    }

    companion object {
        const val UNIQUE_NAME = "bulwark-device-agent"
    }
}
