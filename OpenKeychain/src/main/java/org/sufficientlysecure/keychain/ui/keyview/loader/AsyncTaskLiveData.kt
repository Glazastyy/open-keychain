package org.sufficientlysecure.keychain.ui.keyview.loader

import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.LiveData
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Kotlin-coroutine successor to the old AsyncTask-based loader of the same name.
 * Subclasses (still Java) are unaffected: they only see [asyncLoadData] and
 * [updateDataInBackground], same as before.
 */
abstract class AsyncTaskLiveData<T>(
    private val context: Context,
    private val observedUri: Uri?
) : LiveData<T>() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var loadJob: Job? = null

    private val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun deliverSelfNotifications() = true

        override fun onChange(selfChange: Boolean) {
            updateDataInBackground()
        }
    }

    protected abstract fun asyncLoadData(): T

    protected fun updateDataInBackground() {
        loadJob?.cancel()
        loadJob = scope.launch {
            val result = withContext(Dispatchers.IO) { asyncLoadData() }
            value = result
        }
    }

    override fun onActive() {
        if (value == null) {
            updateDataInBackground()
        }

        if (observedUri != null) {
            context.contentResolver.registerContentObserver(observedUri, true, observer)
        }
    }

    override fun onInactive() {
        loadJob?.cancel()
        loadJob = null

        // NOTE: the previous Java version registered the observer again here instead of
        // unregistering it — a pre-existing bug fixed as part of this rewrite.
        if (observedUri != null) {
            context.contentResolver.unregisterContentObserver(observer)
        }
    }

    protected fun getContext(): Context = context
}
