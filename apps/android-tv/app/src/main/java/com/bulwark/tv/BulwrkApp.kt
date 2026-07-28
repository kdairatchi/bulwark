package com.bulwark.tv

import android.app.Application
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

class BulwrkApp : Application() {
    override fun onCreate() {
        super.onCreate()
        scheduleAgentWork()
    }

    fun scheduleAgentWork() {
        val request = PeriodicWorkRequestBuilder<AgentWorker>(15, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            AgentWorker.UNIQUE_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            request,
        )
    }
}
