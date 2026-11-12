package com.sy.deunlock.android.bond

import android.util.Log
import java.io.File

/**
 * Remembers that this phone's bond is not recognised by the computer on the
 * other end.
 *
 * The desktop can lose its side of a bond (a reinstall, a wiped state dir, an
 * operator revoking on the desktop). The phone cannot tell that apart from
 * "the desktop is out of range": it connects, finds no session service, and
 * retries forever, while the UI keeps claiming the phone is paired — so a fresh
 * `deunlock pair-code` has nowhere to be typed (AUDIT-001 D-26).
 *
 * This marker is the phone's memory of that conclusion. It survives process
 * death (a file, not a field) and it deliberately does **not** delete the bond
 * or its Keystore key: the key is only destroyed by an explicit revoke.
 */
public object DesktopForgotMarker {
    private const val FILE_NAME: String = "desktop_forgot_bond"
    private const val LOG_TAG: String = "deunlock.bond.forgot"

    /** Record that the desktop refused to present this phone's session service. */
    public fun mark(storageDir: File) {
        runCatching {
            File(storageDir, FILE_NAME).writeText(System.currentTimeMillis().toString())
        }.onSuccess {
            Log.w(LOG_TAG, "desktop no longer recognises this bond; pairing required")
        }.onFailure {
            Log.w(LOG_TAG, "could not record a forgotten bond", it)
        }
    }

    /** Drop the marker — a new bond was just persisted, or a pairing started. */
    public fun clear(storageDir: File) {
        runCatching {
            val file = File(storageDir, FILE_NAME)
            if (file.exists() && file.delete()) {
                Log.i(LOG_TAG, "forgotten-bond marker cleared")
            }
        }
    }

    /** Has this phone concluded that the desktop forgot it? */
    public fun isMarked(storageDir: File): Boolean = File(storageDir, FILE_NAME).isFile
}
