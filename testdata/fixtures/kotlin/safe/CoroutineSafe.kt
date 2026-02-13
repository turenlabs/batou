package com.example.safe

import kotlinx.coroutines.*

class SafeTaskRunner {

    // Safe: using CoroutineExceptionHandler
    private val handler = CoroutineExceptionHandler { _, exception ->
        println("Coroutine failed: ${exception.message}")
    }

    // Safe: structured concurrency with coroutineScope
    suspend fun performCriticalTask() = coroutineScope {
        launch {
            val authResult = authenticate()
            if (authResult.isSuccess) {
                grantAccess()
            }
        }
    }

    // Safe: using SupervisorJob with handler
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + handler)

    fun fetchSensitiveData(): Deferred<String> {
        return scope.async {
            loadSecretFromVault()
        }
    }

    private suspend fun authenticate(): Result<Boolean> {
        return Result.success(true)
    }

    private fun grantAccess() {}
    private suspend fun loadSecretFromVault(): String = "secret"
}
