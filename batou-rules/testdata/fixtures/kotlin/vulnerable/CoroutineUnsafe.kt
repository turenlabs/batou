package com.example.vulnerable

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.async

class TaskRunner {

    // Vulnerable: GlobalScope.launch without exception handler
    fun performCriticalTask() {
        GlobalScope.launch {
            val authResult = authenticate()
            if (authResult.isSuccess) {
                grantAccess()
            }
        }
    }

    // Vulnerable: GlobalScope.async without exception handler
    fun fetchSensitiveData(): kotlinx.coroutines.Deferred<String> {
        return GlobalScope.async {
            loadSecretFromVault()
        }
    }

    private suspend fun authenticate(): Result<Boolean> {
        return Result.success(true)
    }

    private fun grantAccess() {}
    private suspend fun loadSecretFromVault(): String = "secret"
}
