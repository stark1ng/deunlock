// Roadmap item S-011 — long-running foreground `Service`.
//
// Before S-011 this class extended `CompanionDeviceService` so the OS
// bound it via the CDM proximity-observation callback. That model
// failed in field tests because CDM's `onDeviceAppeared` fires only on
// transitions; if the bonded peer was "already present" at boot, the
// service never started and `pam_deunlock` saw `response-timeout` on
// every unlock. S-011 inverts the relationship: the service is a
// plain long-running `android.app.Service` that `MainActivity`
// explicitly starts via `startForegroundService` whenever a bond
// record exists. The service holds one `PersistentGattClient` per
// bonded peer (autoConnect=true) so the OS handles reconnection
// silently across range transitions, and surfaces a low-priority
// notification on the `deunlock-presence` channel so the OS keeps the
// process alive across doze.
//
// S-013 collapsed the Android-side topology to a single path: the
// service holds one `PersistentGattClient` per bonded peer and the
// legacy CDM-style direct-controller extension point is gone.
package com.sy.deunlock.android.bg

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationCompat
import com.sy.deunlock.android.bond.BOND_RECORD_FILE_NAME
import com.sy.deunlock.android.bond.BondRecord
import com.sy.deunlock.android.bond.loadPersistedBond
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Log tag used by every span the service emits. Pinned constant
 * because the field-inspection workflow (AGENTS.md /bt skill, Phase 5)
 * greps logcat by tag.
 */
internal const val DEUNLOCK_BG_LOG_TAG: String = "deunlock.bg"

/**
 * Notification channel id the foreground service uses. Pinned so
 * `adb shell dumpsys notification | grep deunlock-presence` is one
 * grep away in field debugging.
 */
public const val NOTIFICATION_CHANNEL_ID: String = "deunlock-presence"

/**
 * Human-readable channel name surfaced in `Settings → Apps → deunlock
 * → Notifications`. The "active" suffix tells the operator the
 * notification is the "service is alive" chip, not an actionable
 * prompt.
 */
public const val NOTIFICATION_CHANNEL_NAME: String = "deunlock phone-as-key active"

/**
 * Channel description shown under the name in the system UI. Tells
 * the operator that muting this channel is safe — the unlock prompts
 * use a separate, high-importance channel.
 */
public const val NOTIFICATION_CHANNEL_DESCRIPTION: String =
    "Background bridge that keeps the BLE link to your desktop alive."

/**
 * Stable notification id under which the foreground notification is
 * posted. Pinned int so `NotificationManager.cancel(NOTIFICATION_ID)`
 * works from any future caller without re-deriving it from a hash.
 */
public const val NOTIFICATION_ID: Int = 1001

/**
 * Foreground-service type. Pinned to `CONNECTED_DEVICE` because the
 * service exists exclusively to hold a BLE link to the bonded
 * desktop; declaring it accurately satisfies Android 14+'s
 * type-enforcement check (which throws
 * `SecurityException` otherwise at `startForeground` time).
 */
internal const val FOREGROUND_SERVICE_TYPE: Int =
    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE

/**
 * Notification title. The operator can mute the channel from the
 * notification's long-press menu once they have seen the chip.
 */
internal const val NOTIFICATION_TITLE: String = "deunlock phone-as-key active"

/**
 * Notification body. Short, plain text — no actionable affordances.
 */
internal const val NOTIFICATION_BODY: String =
    "Keeping the BLE link to your desktop alive."

/**
 * Provider that yields the in-service notification icon. Production
 * uses a stable system drawable; tests use the same. Held as a
 * compile-time constant so the resource lookup happens once at
 * build time.
 */
internal val NOTIFICATION_ICON: Int = android.R.drawable.ic_lock_lock

/**
 * Provider that resolves a bonded peer's hostname (for the
 * notification title). Tests inject a fixed mapping; production
 * wires a query against the bond store once that surface exists in
 * UniFFI (tracked as a follow-up; for S-018 the hostname falls
 * back to the association's `displayName`).
 */
public fun interface HostnameResolver {
    public fun hostnameFor(peerId: String): String
}

/**
 * Roadmap item S-015 — resolves a bonded peer's per-bond Keystore
 * alias for the Ed25519 private key minted at pair time by
 * `AndroidKeystoreKeyGenerator` (DEV-002). The activity needs the
 * alias on Approve so the production `AndroidBiometricGate` can
 * open the `PrivateKey` from the AndroidKeyStore and wrap it in a
 * `BiometricPrompt.CryptoObject` for the per-use sign. Tests inject
 * a fixed mapping; production wires this in
 * `MainActivity.installCompanionSeams`.
 */
public fun interface KeystoreAliasResolver {
    public fun keystoreAliasFor(peerId: String): String
}

/**
 * Provider that resolves a peer's bond key (the BLAKE3 keyed-hash
 * key used by UniFFI's `verifyChallengeFrame`). Production wires
 * this to the bond store; tests inject a fixed map.
 *
 * Returns `null` when the peer is unknown — the service then drops
 * the frame silently.
 */
public fun interface BondKeyProvider {
    public fun bondKeyFor(peerId: String): ByteArray?
}

/**
 * Adapter so the service can call into the Rust UniFFI surface
 * without statically importing `uniffi.deunlock_mobile` (which
 * blows up the JVM unit-test classpath with `UnsatisfiedLinkError`
 * unless the AAR is present).
 *
 * Production wires `UniffiChallengeVerifier` (below); tests inject
 * a fake.
 */
/**
 * Computes the exact byte string the phone must sign for one challenge frame.
 *
 * Wire v2 signs an *auth transcript* (`deunlock-auth-v2` ‖ version ‖ host_id ‖
 * service ‖ user ‖ nonce ‖ issued_at), not the frame body: the desktop bound the
 * answer to the question it asked (AUDIT-001 D-04), so a signature over
 * `version ‖ nonce ‖ payload` no longer verifies. Deriving those bytes here, by
 * hand, is how the two halves drifted apart once already — the approval path
 * kept stripping a 16-byte tag and signing a body the daemon stopped checking
 * in v2, which surfaced only as `bad-signature` with a valid key.
 *
 * So the bytes come from the same Rust parser the desktop's transcript comes
 * from: `parse_challenge` MAC-checks the frame first (nothing is signed before
 * the phone has proven the frame came from its bonded peer) and returns
 * `sign_payload` already normalized across v1 and v2.
 *
 * `null` means "do not sign": unknown peer, missing bond key, bad MAC, or a
 * malformed frame. The caller drops the challenge silently.
 */
public fun interface SigningPayloadProvider {
    public fun signingPayloadFor(bondKey: ByteArray, frameBytes: ByteArray): ByteArray?
}

/** Production [SigningPayloadProvider] backed by UniFFI's `parse_challenge`. */
public class UniffiSigningPayloadProvider : SigningPayloadProvider {
    override fun signingPayloadFor(bondKey: ByteArray, frameBytes: ByteArray): ByteArray? =
        try {
            uniffi.deunlock_mobile.parseChallenge(bondKey, frameBytes).signPayload
        } catch (t: Throwable) {
            null
        }
}

public fun interface ChallengeVerifier {
    /**
     * Verify [frameBytes] under [bondKey]. Returns the verified
     * challenge payload bytes on success, or `null` on any verify
     * failure / malformed frame.
     */
    public fun verify(bondKey: ByteArray, frameBytes: ByteArray): ByteArray?
}

/**
 * Production [ChallengeVerifier] backed by UniFFI's
 * `verifyChallengeFrame(bondKey, frameBytes)`.
 */
public class UniffiChallengeVerifier : ChallengeVerifier {
    override fun verify(bondKey: ByteArray, frameBytes: ByteArray): ByteArray? =
        try {
            uniffi.deunlock_mobile.verifyChallengeFrame(bondKey, frameBytes)
        } catch (t: Throwable) {
            null
        }
}

/**
 * Opaque handle for a managed GATT client the service owns. The
 * service constructs one instance per bonded peer at `onCreate` and
 * calls `stop()` on every instance at `onDestroy`.
 *
 * Production binds this to [PersistentGattClient] via a closure in
 * the [GattClientFactory] returned by `MainActivity`'s installer.
 * Tests bind a recording fake.
 */
public interface ManagedClient {
    /** Open the underlying GATT link. Idempotent. */
    public fun start()

    /** Tear down the underlying GATT link. Idempotent. */
    public fun stop()
}

/**
 * Provider that constructs a [ManagedClient] for one bonded peer.
 * Production: wraps `PersistentGattClient`. Tests: returns a
 * recording fake.
 */
public fun interface GattClientFactory {
    public fun create(bond: BondRecord): ManagedClient
}

/**
 * Production [ManagedClient] that delegates to a [PersistentGattClient].
 * Kept as a thin adapter so the foreground service can hold a generic
 * `ManagedClient` reference (which keeps the test seam clean) without
 * the production call site having to fabricate one inline.
 */
public class PersistentManagedClient(
    private val client: PersistentGattClient,
) : ManagedClient {
    override fun start() {
        client.start()
    }

    override fun stop() {
        client.stop()
    }
}

/**
 * Provider that yields the list of currently-bonded peers. Production
 * delegates to `loadPersistedBond(filesDir)` and wraps the single
 * record in a one-element list when present. Tests pre-seed an
 * arbitrary list. Returning an empty list means "no bonds; do not
 * inject any clients".
 */
public fun interface BondListProvider {
    public fun bonds(): List<BondRecord>
}

public class DeUnlockCompanionService : Service() {

    /**
     * Per-peer GATT client. Keyed by `BondRecord.peerId` so multi-bond
     * deployments scale without refactor.
     */
    private val clients: ConcurrentHashMap<String, ManagedClient> =
        ConcurrentHashMap()

    /**
     * The foreground type passed to the most recent `startForeground`
     * call. Robolectric 4.11.1's `ShadowService` does not expose
     * `getForegroundServiceType()`, so the test reads this field
     * directly. Package-internal — only the test friend reads it.
     */
    internal var lastForegroundType: Int = 0
        private set

    private val radioReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> clients.values.forEach { it.stop() }
                BluetoothAdapter.STATE_ON -> clients.values.forEach { it.start() }
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        val notification = buildForegroundNotification()
        startForegroundCompat(notification)
        ensureDefaultGattClientFactory()
        ensureDefaultCompanionSeams()
        ContextCompat.registerReceiver(this, radioReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED), ContextCompat.RECEIVER_EXPORTED)
        injectClientsForBonds()
        isRunning.set(true)
        Log.i(DEUNLOCK_BG_LOG_TAG, "onCreate: foreground up, clients=${clients.size}")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // The service is "sticky" — if the OS kills the process, the
        // system tries to recreate it. `onCreate` will re-run the
        // bond-injection path on every recreate.
        return START_STICKY
    }

    override fun onDestroy() {
        unregisterReceiver(radioReceiver)
        for ((peerId, client) in clients) {
            runCatching { client.stop() }
                .onFailure {
                    Log.w(DEUNLOCK_BG_LOG_TAG, "onDestroy: client.stop failed peer=$peerId", it)
                }
        }
        clients.clear()
        isRunning.set(false)
        Log.i(DEUNLOCK_BG_LOG_TAG, "onDestroy: clients torn down")
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val existing = manager.getNotificationChannel(NOTIFICATION_CHANNEL_ID)
        if (existing != null) return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            NOTIFICATION_CHANNEL_NAME,
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = NOTIFICATION_CHANNEL_DESCRIPTION
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
        if (channelCreatedLogged.compareAndSet(false, true)) {
            Log.i(DEUNLOCK_BG_LOG_TAG, "channel created id=$NOTIFICATION_CHANNEL_ID")
        }
    }

    private fun buildForegroundNotification(): Notification =
        NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle(NOTIFICATION_TITLE)
            .setContentText(NOTIFICATION_BODY)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setSmallIcon(NOTIFICATION_ICON)
            .build()

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, FOREGROUND_SERVICE_TYPE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        lastForegroundType = FOREGROUND_SERVICE_TYPE
    }

    private fun injectClientsForBonds() {
        val factory = gattClientFactory ?: return
        val provider = bondListProvider ?: defaultBondListProvider()
        for (bond in provider.bonds()) {
            val client = factory.create(bond)
            clients[bond.peerId] = client
            runCatching { client.start() }
                .onFailure {
                    Log.w(DEUNLOCK_BG_LOG_TAG, "client.start failed peer=${bond.peerId}", it)
                }
        }
    }

    /**
     * BUG-20260522-0130: when Android kills the app process under
     * memory pressure and `START_STICKY` resurrects the service, the
     * companion-object [gattClientFactory] is reset to `null` because
     * the entire JVM was torn down. `MainActivity` is the only place
     * the production factory was previously installed, so a service
     * resurrected without the UI being reopened would sit alive with
     * `clients = []` forever — every challenge from the desktop
     * instant-failed `transport-error`. This installer runs inside
     * `onCreate` so a process-restarted service is self-sufficient.
     *
     * Mirrors `MainActivity.installPersistentClientFactory` field-by-
     * field; the activity's installer remains as a no-op when the
     * default is already in place (the `gattClientFactory != null`
     * guard there short-circuits cleanly).
     */
    private fun ensureDefaultGattClientFactory() {
        if (gattClientFactory != null) return
        val adapter = runCatching {
            getSystemService(BluetoothManager::class.java)?.adapter
        }.getOrNull()
        if (adapter == null) {
            Log.w(
                DEUNLOCK_BG_LOG_TAG,
                "ensureDefaultGattClientFactory: no BluetoothAdapter; clients will stay empty until MainActivity installs a factory",
            )
            return
        }
        val appContext = applicationContext
        gattClientFactory = GattClientFactory { bond ->
            val client = PersistentGattClient(
                context = appContext,
                adapter = adapter,
                peerId = bond.peerId,
                deviceMac = bond.peerId,
                onChallenge = { peerId, frameBytes ->
                    // A revoked bond still has to reach the desktop, and this is
                    // the only moment it can: the phone cannot open a socket, so
                    // the revocation rides the challenge it is being asked to
                    // answer. Answering it with the revoke frame is also the
                    // honest reply - this phone will never approve for that
                    // desktop again (AUDIT-001 D-14).
                    val signingPayload = if (deliverPendingRevoke(peerId)) {
                        null
                    } else {
                        signingPayloadFor(peerId, frameBytes)
                    }
                    if (signingPayload == null) {
                        Log.w(
                            DEUNLOCK_BG_LOG_TAG,
                            "challenge dropped: no signing payload peer=$peerId (unknown bond, bad MAC, or unsupported wire version)",
                        )
                    } else {
                        launchApprovalActivity(appContext, peerId, signingPayload)
                    }
                },
            )
            PersistentGattClientRegistry.put(bond.peerId, client)
            PersistentManagedClient(client)
        }
        Log.i(
            DEUNLOCK_BG_LOG_TAG,
            "ensureDefaultGattClientFactory: installed (MainActivity had not yet)",
        )
    }

    /**
     * BUG-20260522-0138 (extension): the original fix installed a
     * default `gattClientFactory` so the persistent BLE link came up
     * after a `START_STICKY` resurrect. That unblocked transport but
     * the **approval path** then failed with `alias=''` because
     * `keystoreAliasResolver`, `hostnameResolver`, `bondKeyProvider`,
     * `challengeVerifier`, and the activity-level
     * [ChallengeApprovalActivity.responseSink] /
     * [ChallengeApprovalActivity.cancelSink] are also JVM-static
     * seams owned by `MainActivity.installCompanionSeams`. Each gets
     * wiped by the process-restart and the user observes "Approve
     * tap closes the app without biometric → desktop PAM falls back
     * to FIDO2."
     *
     * This helper mirrors `MainActivity.installCompanionSeams`
     * load-bearing assignments using the persisted bond record as the
     * source of truth. It does **not** install
     * [ChallengeApprovalActivity.historyDispatcher] — history
     * notifications are UI-tier and the responseSink default
     * dispatches a `null`-safe history payload when no dispatcher is
     * present (the post-restart user gets unlock back; the history
     * surface re-attaches when they next open the app).
     */
    private fun ensureDefaultCompanionSeams() {
        val appContext = applicationContext
        val recordSupplier: () -> BondRecord? = {
            runCatching { loadPersistedBond(appContext.filesDir) }.getOrNull()
        }
        if (bondKeyProvider == null) {
            bondKeyProvider = BondKeyProvider { peerId ->
                recordSupplier()?.takeIf { it.peerId == peerId }?.bondKey
            }
        }
        if (hostnameResolver == null) {
            hostnameResolver = HostnameResolver { peerId ->
                recordSupplier()?.takeIf { it.peerId == peerId }?.hostName ?: peerId
            }
        }
        if (keystoreAliasResolver == null) {
            keystoreAliasResolver = KeystoreAliasResolver { peerId ->
                recordSupplier()?.takeIf { it.peerId == peerId }?.keystoreAlias.orEmpty()
            }
        }
        if (challengeVerifier == null) {
            challengeVerifier = UniffiChallengeVerifier()
        }
        if (ChallengeApprovalActivity.responseSink == null) {
            ChallengeApprovalActivity.responseSink = ResponseSink { peerId, responseBytes ->
                val client = PersistentGattClientRegistry.lookup(peerId)
                if (client == null) {
                    Log.w(DEUNLOCK_BG_LOG_TAG, "approve: no persistent client for peer=$peerId")
                } else {
                    runCatching { client.writeResponse(responseBytes) }
                        .onFailure {
                            Log.w(DEUNLOCK_BG_LOG_TAG, "approve: writeResponse failed peer=$peerId", it)
                        }
                }
            }
        }
        if (ChallengeApprovalActivity.cancelSink == null) {
            ChallengeApprovalActivity.cancelSink = CancelSink { peerId, deniedFrameBytes ->
                val client = PersistentGattClientRegistry.lookup(peerId)
                if (client == null) {
                    Log.w(DEUNLOCK_BG_LOG_TAG, "cancel: no persistent client for peer=$peerId")
                } else {
                    runCatching { client.writeResponse(deniedFrameBytes) }
                        .onFailure {
                            Log.w(DEUNLOCK_BG_LOG_TAG, "cancel: writeResponse failed peer=$peerId", it)
                        }
                }
            }
        }
        Log.i(
            DEUNLOCK_BG_LOG_TAG,
            "ensureDefaultCompanionSeams: installed missing seams (MainActivity had not yet)",
        )
    }

    /**
     * Tell the desktop that this bond was revoked, if a tombstone is pending.
     *
     * Returns true when the frame was written, in which case the challenge has
     * been answered (the desktop verifies it, deletes its half and reports
     * `bond-revoked`) and the caller must not open the approval UI. Returns
     * false when there is no tombstone, or when delivery failed — in which case
     * the tombstone stays and the next contact tries again.
     */
    private fun deliverPendingRevoke(peerId: String): Boolean {
        val record = runCatching { loadPersistedBond(filesDir) }.getOrNull() ?: return false
        if (!record.revokePending || record.peerId != peerId) return false
        if (record.revokeDeadlineMs != 0L && System.currentTimeMillis() > record.revokeDeadlineMs) {
            Log.i(DEUNLOCK_BG_LOG_TAG, "revoke: tombstone expired undelivered; dropping peer=$peerId")
            runCatching { java.io.File(filesDir, BOND_RECORD_FILE_NAME).delete() }
            return false
        }
        val frame = runCatching {
            uniffi.deunlock_mobile.buildRevoke(record.bondKey, System.currentTimeMillis().toULong())
        }.getOrElse {
            Log.w(DEUNLOCK_BG_LOG_TAG, "revoke: could not build the frame peer=$peerId", it)
            return false
        }
        val client = PersistentGattClientRegistry.lookup(peerId)
        if (client == null) {
            Log.i(DEUNLOCK_BG_LOG_TAG, "revoke: no client yet peer=$peerId; will retry on the next contact")
            return false
        }
        val written = runCatching { client.writeResponse(frame) }.getOrDefault(false)
        if (!written) {
            Log.w(DEUNLOCK_BG_LOG_TAG, "revoke: write failed peer=$peerId; tombstone kept")
            return false
        }
        runCatching { java.io.File(filesDir, BOND_RECORD_FILE_NAME).delete() }
        Log.i(DEUNLOCK_BG_LOG_TAG, "revoke: delivered to the desktop peer=$peerId; tombstone cleared")
        return true
    }

    private fun defaultBondListProvider(): BondListProvider = BondListProvider {
        val record = runCatching { loadPersistedBond(filesDir) }.getOrNull()
        if (record == null) emptyList() else listOf(record)
    }

    public companion object {
        internal const val LOG_TAG: String = DEUNLOCK_BG_LOG_TAG

        /**
         * Latches the "channel created" log so it appears at most once
         * per process lifetime — first creation logs, every subsequent
         * `ensureNotificationChannel` call no-ops silently.
         */
        private val channelCreatedLogged: AtomicBoolean = AtomicBoolean(false)

        /**
         * Process-local lifecycle flag the S-012 resurrection helper
         * consults. `true` while `onCreate` has run and `onDestroy`
         * has not; `false` otherwise (cold-start default, post-destroy).
         * The flag survives only inside the app process — a separate
         * `WORK_PROCESS` worker would read `false` here even when the
         * service is alive elsewhere, which is acceptable because
         * `startForegroundService` is idempotent at the OS layer.
         */
        public val isRunning: AtomicBoolean = AtomicBoolean(false)

        /** Bond-key provider seam; see [BondKeyProvider]. */
        @Volatile
        public var bondKeyProvider: BondKeyProvider? = null

        /** Hostname resolver seam; see [HostnameResolver]. */
        @Volatile
        public var hostnameResolver: HostnameResolver? = null

        /**
         * Keystore-alias resolver seam (S-015); see
         * [KeystoreAliasResolver]. Production wires this from
         * `MainActivity.installCompanionSeams` to the bond record's
         * `keystoreAlias`. Tests inject a fixed map. When `null` the
         * alias extra is empty and the activity falls through to a
         * denied frame on Approve (the OS Keystore would reject the
         * `getKey(null, ...)` anyway).
         */
        @Volatile
        public var keystoreAliasResolver: KeystoreAliasResolver? = null

        /** Challenge verifier seam; see [ChallengeVerifier]. */
        @Volatile
        public var challengeVerifier: ChallengeVerifier? = null

        /**
         * Persistent-client factory. Production sets this from
         * `MainActivity.onCreate`; tests inject a recording fake.
         */
        @Volatile
        public var gattClientFactory: GattClientFactory? = null

        /**
         * Bond-list provider seam. Production leaves it `null`, in
         * which case the service falls back to
         * `loadPersistedBond(filesDir)`; tests inject a fixed list.
         */
        @Volatile
        public var bondListProvider: BondListProvider? = null

        /**
         * Reset all seams to `null`. Used by Robolectric tests to keep
         * state clean between cases.
         */
        public fun resetSeams() {
            bondKeyProvider = null
            hostnameResolver = null
            keystoreAliasResolver = null
            challengeVerifier = null
            gattClientFactory = null
            bondListProvider = null
        }

        /**
         * Roadmap item S-014 — launch [ChallengeApprovalActivity] for a
         * fresh challenge frame the [PersistentGattClient.onChallenge]
         * callback delivered.
         *
         * The hostname comes from the installed [hostnameResolver]
         * (which `MainActivity.installCompanionSeams` wires to the
         * bond record's `hostName`). If no resolver is installed the
         * peer id is used as the displayed hostname so the prompt
         * still renders something the user can recognise — see SPEC
         * §9 Q2 for the prompt copy contract.
         *
         * The intent is dispatched via [PendingIntent.getActivity]
         * with `FLAG_IMMUTABLE` (Android 12+ floor) so the OS treats
         * the launch as foreground-equivalent and the activity's
         * `showWhenLocked` / `turnScreenOn` manifest attributes wake
         * the screen over the keyguard.
         */
        /**
         * Resolve the bytes the phone signs for [frameBytes] under the bond of
         * [peerId], or `null` when this phone must not answer at all.
         */
        internal fun signingPayloadFor(peerId: String, frameBytes: ByteArray): ByteArray? {
            val bondKey = bondKeyProvider?.bondKeyFor(peerId) ?: return null
            return signingPayloadProvider.signingPayloadFor(bondKey, frameBytes)
        }

        /**
         * Seam for the v2 signing payload (see [SigningPayloadProvider]).
         * Replaced in JVM tests, where the UniFFI native library is absent.
         */
        public var signingPayloadProvider: SigningPayloadProvider = UniffiSigningPayloadProvider()

        public fun launchApprovalActivity(
            context: Context,
            peerId: String,
            challengeBytes: ByteArray,
        ) {
            val hostname = hostnameResolver?.hostnameFor(peerId) ?: peerId
            val keystoreAlias = keystoreAliasResolver?.keystoreAliasFor(peerId).orEmpty()
            val intent = buildApprovalIntent(
                context = context,
                peerId = peerId,
                hostname = hostname,
                challengeBytes = challengeBytes,
                keystoreAlias = keystoreAlias,
            )
            val pending = PendingIntent.getActivity(
                context,
                APPROVAL_PENDING_REQUEST_CODE,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            runCatching { pending.send() }
                .onFailure { Log.w(DEUNLOCK_BG_LOG_TAG, "approval pending-intent send failed peer=$peerId", it) }
        }
    }
}

/**
 * Roadmap item S-014 — request code passed to
 * `PendingIntent.getActivity`. Pinned constant so a future caller
 * does not collide on the same request code by accident.
 */
internal const val APPROVAL_PENDING_REQUEST_CODE: Int = 0x5A14
