// Roadmap item S-014 — `ChallengeApprovalActivity` (transparent,
// over-keyguard). Roadmap item S-015 — BiometricPrompt
// (`BIOMETRIC_STRONG`) + Keystore Ed25519 sign on Approve.
//
// `DeUnlockCompanionService` launches this activity via
// `PendingIntent.getActivity` on every fresh challenge frame the
// `PersistentGattClient.onChallenge` callback delivers. The activity
// is `noHistory="true"`, `launchMode="singleInstance"`, and
// declares `android:showWhenLocked="true"` / `android:turnScreenOn="true"`
// in `AndroidManifest.xml`; the OS therefore wakes the screen and
// renders the activity over the keyguard.
//
// The prompt copy is the SPEC §9 Q2 answer verbatim:
//
//     "$hostname is requesting sudo (peer_id $short)"
//
// where `$short` is the last three octets of the peer's MAC. The
// hostname comes from `EXTRA_HOSTNAME` (which the service populates
// from the bond record's `hostName` — never from the incoming frame),
// pinning the SPEC §9 Q2 guarantee at the activity boundary.
//
// On Cancel, the activity writes a denied frame back through the
// same GATT connection by handing the bytes to the
// `DeUnlockCompanionService` companion seam [CancelSink]; production
// wires the sink to `PersistentGattClient.writeResponse(...)`.
//
// On Approve (S-015), the activity hands the bond's
// `EXTRA_KEYSTORE_ALIAS` and the verbatim `EXTRA_CHALLENGE_BYTES` to
// the [BiometricGate] companion seam. The production
// implementation builds a `BiometricPrompt` whose
// `PromptInfo.allowedAuthenticators = BIOMETRIC_STRONG` (no
// DEVICE_CREDENTIAL fallback), opens the Keystore-resident Ed25519
// PrivateKey under the alias, wraps it in a `Signature` +
// `BiometricPrompt.CryptoObject`, runs the prompt, and — on
// `onAuthenticationSucceeded` — calls
// `sig.update(challengeBytes); sig.sign()` to produce the 64-byte
// response payload. The bytes flow to the [ResponseSink] companion
// seam; production wires it to
// `PersistentGattClient.writeResponse(...)` on the same connection
// the challenge arrived on. On biometric fail / cancel, the activity
// writes `DENIED_FRAME_BYTES` via the response sink. SPEC §3.2 D6
// per-use auth + §7 T-Relay defense pin this contract.
//
// The denied-frame wire shape is the SPEC v1 frame layout
// (`[version:1] || [nonce:16] || [signature:64] || [tag:16]`) with
// the signature payload filled with `DENIED_FRAME_BYTES` (64 zero
// bytes). The daemon's `verify_response` rejects with `BadSignature`
// → maps to `PAM_AUTH_ERR`, which is the right end-state for an
// explicit user denial (the alternative — sending nothing — would
// map to `PAM_AUTHINFO_UNAVAIL`, a fall-through, which is wrong for
// a user "no").
//
// Journey:
// - `specs/journeys/JOURNEY-S-014-challenge-approval-activity.md`
//   (activity lifecycle + Cancel path).
// - `specs/journeys/JOURNEY-S-015-biometric-keystore-sign.md`
//   (BiometricPrompt + Keystore sign).
package com.sy.deunlock.android.bg

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.lifecycle.lifecycleScope
import com.sy.deunlock.android.ui.theme.SyBorder
import com.sy.deunlock.android.ui.theme.SyDanger
import com.sy.deunlock.android.ui.theme.SySuccess
import com.sy.deunlock.android.ui.theme.SyTextDim
import com.sy.deunlock.android.ui.theme.SyWarning
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.sy.deunlock.android.R
import com.sy.deunlock.android.ui.theme.DeUnlockTheme
import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/** Intent extra carrying the bonded peer's stable id (the MAC). */
public const val EXTRA_PEER_ID: String = "deunlock.peerId"

/** Intent extra carrying the bond's hostname, read from `BondRecord.hostName`. */
public const val EXTRA_HOSTNAME: String = "deunlock.hostname"

/** Intent extra carrying the verbatim challenge frame body bytes the daemon notified. */
public const val EXTRA_CHALLENGE_BYTES: String = "deunlock.challengeBytes"

/**
 * Intent extra carrying the bond's Keystore alias for the per-bond
 * Ed25519 private key minted at pair time by
 * [com.sy.deunlock.android.pair.impl.AndroidKeystoreKeyGenerator]
 * (DEV-002). S-015 reads this on Approve to open the
 * `PrivateKey` from the AndroidKeyStore.
 */
public const val EXTRA_KEYSTORE_ALIAS: String = "deunlock.keystoreAlias"

/**
 * Logcat tag the activity emits under. Pinned constant so
 * `adb logcat -s deunlock.bg.approve` is one grep away.
 */
internal const val APPROVAL_LOG_TAG: String = "deunlock.bg.approve"

/**
 * Reason byte name surfaced in journey docs. Wired to the signature
 * payload below; kept as a named constant so the audit-trail link
 * "denied frame == 64 zero bytes" is a one-grep contract.
 */
public const val DENIED_FRAME_REASON: String = "denied"

/** Length in bytes of an Ed25519 signature; matches `deunlock-core::sign::SIGNATURE_LEN`. */
internal const val SIGNATURE_LEN: Int = 64

/** Number of trailing peer-id chars rendered as `$short` in the SPEC §9 Q2 prompt. */
internal const val SHORT_PEER_ID_LEN: Int = 8

/**
 * SPEC §3.2 D6 + §7 T-Relay defense: the BiometricPrompt's allowed
 * authenticator bitmask. `BIOMETRIC_STRONG` ONLY — no
 * `DEVICE_CREDENTIAL` fallback. The SPEC §3 Decisions row
 * "Keystore auth window" forbids PIN/pattern/password because they
 * are weaker than Class-3 biometric and do not solve the
 * relay-tap-latency story.
 */
public const val STRONG_AUTHENTICATOR: Int =
    BiometricManager.Authenticators.BIOMETRIC_STRONG

/**
 * JCA signature algorithm name for the bond's Ed25519 private key.
 * The same string the host JVM (`SunEC` since JDK 15) and the
 * Android Keystore (`AndroidKeyStore` since API 33) both resolve.
 */
internal const val ED25519_ALGORITHM: String = "Ed25519"

/** Android Keystore provider name. */
internal const val KEYSTORE_PROVIDER: String = "AndroidKeyStore"

/** Resource id of the BiometricPrompt title string. */
public val PROMPT_TITLE_RES: Int = R.string.deunlock_biometric_prompt_title

/** Resource id of the BiometricPrompt subtitle format string (`%1$s`=hostname, `%2$s`=short peer id). */
public val PROMPT_SUBTITLE_FMT: Int = R.string.deunlock_biometric_prompt_subtitle_fmt

/** Resource id of the BiometricPrompt negative-button text. */
public val PROMPT_NEGATIVE_RES: Int = R.string.deunlock_biometric_prompt_cancel

/**
 * Signature payload the activity writes back as the denied frame.
 *
 * The daemon's `verify_response` then rejects with `BadSignature`
 * → maps to `PAM_AUTH_ERR`. See the file header for the rationale
 * versus "send nothing" (`PAM_AUTHINFO_UNAVAIL`).
 */
public val DENIED_FRAME_BYTES: ByteArray = ByteArray(SIGNATURE_LEN) { 0 }

/**
 * Sink the activity calls on Cancel. Production wires it to a service-side
 * helper that resolves the per-peer `PersistentGattClient` and calls
 * `writeResponse(deniedFrameBytes)`; tests inject a recording fake.
 */
public fun interface CancelSink {
    public fun onCancel(peerId: String, deniedFrameBytes: ByteArray)
}

/**
 * Sink the activity calls with the **approve** response — either the
 * 64-byte Ed25519 signature on success, or [DENIED_FRAME_BYTES] on
 * biometric fail / cancel. Production wires it to a service-side
 * helper that resolves the per-peer `PersistentGattClient` and
 * calls `writeResponse(responseBytes)` on the same GATT connection
 * the challenge arrived on; tests inject a recording fake.
 *
 * The separate seam (vs. reusing [CancelSink]) names the
 * approve-side semantics explicitly: the production wiring uses the
 * same `writeResponse` plumbing, but the audit trail distinguishes a
 * signed response from a denied one via the calling sink.
 */
public fun interface ResponseSink {
    public fun onResponse(peerId: String, responseBytes: ByteArray)
}

/**
 * Callback the [BiometricGate] invokes with the terminal outcome of
 * the BiometricPrompt round. Implementations MUST invoke exactly
 * one of [onSucceeded] / [onFailed] per `authenticate(...)` call.
 */
public interface BiometricGateCallback {
    /**
     * BiometricPrompt succeeded; [signatureBytes] is the 64-byte
     * Ed25519 signature over the challenge body the gate signed
     * with the Keystore-resident private key.
     */
    public fun onSucceeded(signatureBytes: ByteArray)

    /**
     * BiometricPrompt was cancelled, errored, or never opened
     * (e.g. no enrolled fingerprint). [reason] is the human-
     * readable cause for the logcat audit trail.
     */
    public fun onFailed(reason: String)
}

/**
 * Test seam wrapping the [BiometricPrompt] + Keystore-sign
 * lifecycle. In production [AndroidBiometricGate] builds a real
 * `BiometricPrompt` whose
 * `PromptInfo.allowedAuthenticators == BIOMETRIC_STRONG`, wraps the
 * Keystore-resident Ed25519 `PrivateKey` under [keystoreAlias] in a
 * `Signature.getInstance("Ed25519").apply { initSign(privateKey) }`,
 * passes that as `BiometricPrompt.CryptoObject(signature)`, and on
 * success calls `sig.update(challengeBytes); sig.sign()` to produce
 * the response payload.
 *
 * In tests a recording fake exposes `succeed(signatureBytes)` /
 * `fail(reason)` methods that drive the activity lifecycle without
 * firing a real prompt — the only way to exercise the activity
 * lifecycle on a Robolectric JVM.
 */
public interface BiometricGate {
    /**
     * Open a fresh BiometricPrompt round bound to a per-use
     * Keystore signing operation. MUST invoke exactly one callback
     * method per call; MUST NOT throw — every failure surface is a
     * typed [BiometricGateCallback.onFailed] call.
     */
    public fun authenticate(
        keystoreAlias: String,
        challengeBytes: ByteArray,
        callback: BiometricGateCallback,
    )

    /**
     * Withdraw a prompt that is still open, if any.
     *
     * Called when the challenge it was opened for is superseded: a second
     * challenge can arrive while the operator's finger is on the sensor
     * (AUDIT-001 D-32), and the answer must be asked again for the frame that is
     * actually open instead of being spent on the old one. Implementations MUST
     * be safe to call when no prompt is open, and the callback of the withdrawn
     * round must not be relied upon afterwards — the caller invalidates it.
     */
    public fun cancel() {
        // No prompt to withdraw.
    }
}

/**
 * Sign the [challengeBytes] under [privateKey] using
 * `Signature.getInstance("Ed25519")`. Returns the 64-byte
 * Ed25519 signature.
 *
 * The signed input is **exactly** [challengeBytes] — the daemon's
 * `verify_response` runs `verify_frame(pubkey, frame, sig)` which
 * verifies under `frame.body_bytes() = version || nonce || payload`
 * (see `crates/deunlock-core/src/sign.rs::sign_frame`). The caller
 * (the [BiometricGate]) MUST pass the body bytes the daemon
 * notified, NOT the full encoded frame with the trailing tag.
 *
 * Top-level so the [KeystoreSignTest] can inject a JVM-generated
 * Ed25519 `PrivateKey` (the Robolectric AndroidKeyStore shadow does
 * not host Ed25519; the host JVM does since JDK 15) without
 * standing up an AndroidKeyStore alias.
 */
public fun signChallenge(privateKey: PrivateKey, challengeBytes: ByteArray): ByteArray {
    val signature = Signature.getInstance(ED25519_ALGORITHM)
    signature.initSign(privateKey)
    signature.update(challengeBytes)
    return signature.sign()
}

/**
 * Transparent, over-keyguard activity launched by
 * `DeUnlockCompanionService` on every fresh challenge frame.
 *
 * Extends `FragmentActivity` because `androidx.biometric:1.2.0-alpha05`'s
 * `BiometricPrompt` binds to the host fragment manager for its
 * dialog lifecycle; a `ComponentActivity` parent class would
 * compile but fail at runtime when the prompt tries to attach.
 */
public class ChallengeApprovalActivity : FragmentActivity() {

    /**
     * Latest `setShowWhenLocked` value the activity passed to the OS.
     * Robolectric 4.11.1's `ShadowActivity` does not expose
     * `isShowWhenLocked()` directly, so the DoD test reads this
     * package-internal field instead.
     */
    internal var lastShowWhenLockedFlag: Boolean = false
        private set

    /** Mirror of [lastShowWhenLockedFlag] for `setTurnScreenOn`. */
    internal var lastTurnScreenOnFlag: Boolean = false
        private set

    /**
     * Latest prompt-text string the Compose tree rendered. Held so the
     * DoD test `hostname_shown_in_prompt` can pin the SPEC §9 Q2 copy
     * without driving Compose's UI-test harness (which would require
     * `ui-test-junit4` on the JVM classpath).
     */
    internal var lastPromptText: String = ""
        private set

    /** Peer the screen is currently asking about (D-31 test seam). */
    internal var lastRenderedPeerId: String = ""
        private set

    /** Challenge bytes the screen is currently asking about (D-31 test seam). */
    internal var lastRenderedChallenge: ByteArray = ByteArray(0)
        private set

    /** Everything the prompt draws; the composable is a pure function of it. */
    private val screen = mutableStateOf(ApprovalScreenState(promptText = ""))

    /** Countdown job for the challenge on screen. */
    private var tickerJob: Job? = null

    private var resolvedPeerId: String = ""
    private var resolvedHostname: String = ""
    private var resolvedChallenge: ByteArray = ByteArray(0)
    private var resolvedKeystoreAlias: String = ""

    /** True while a biometric round is open for the challenge on screen. */
    private var approvalInFlight: Boolean = false

    /** Gate the open round runs on, so a rebind can withdraw it. */
    private var activeGate: BiometricGate? = null

    /**
     * Bumped whenever the challenge on screen is replaced. A callback carrying an
     * older value belongs to a challenge nobody is waiting for any more (D-32).
     */
    private var approvalGeneration: Int = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
            lastShowWhenLockedFlag = true
            lastTurnScreenOnFlag = true
        }
        setContent {
            ApprovalContent(
                state = screen.value,
                reduceMotion = reduceMotion(),
                onApprove = ::onApproveClicked,
                onCancel = ::onCancelClicked,
            )
        }
        bind(intent)
    }

    /**
     * A second challenge while this prompt is already up.
     *
     * `launchMode="singleInstance"` means the service's next
     * `PendingIntent.getActivity` does **not** create an instance — it delivers
     * here. Rendering only in `onCreate` left the first prompt on screen while
     * the desktop was already waiting on a newer challenge, so the operator's
     * approval answered a frame nobody was waiting for (AUDIT-001 D-31; the
     * desktop half of the same story is D-28). Rebind to the newest challenge
     * instead; the older one is abandoned by its caller and needs no answer.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        val superseded = resolvedPeerId
        if (!bind(intent)) {
            return
        }
        Log.i(APPROVAL_LOG_TAG, "re-render peer=$resolvedPeerId superseded=$superseded")
    }

    /**
     * Read a challenge out of [intent] and put it on screen. Returns `false`
     * (after finishing the activity) when the intent does not carry enough to
     * ask a question.
     */
    private fun bind(intent: Intent?): Boolean {
        val peerId = intent?.getStringExtra(EXTRA_PEER_ID).orEmpty()
        val hostname = intent?.getStringExtra(EXTRA_HOSTNAME).orEmpty()
        if (peerId.isEmpty() || hostname.isEmpty()) {
            Log.w(APPROVAL_LOG_TAG, "missing extras peer='$peerId' host='$hostname'; finishing")
            finish()
            return false
        }
        resolvedPeerId = peerId
        resolvedHostname = hostname
        resolvedChallenge = intent?.getByteArrayExtra(EXTRA_CHALLENGE_BYTES) ?: ByteArray(0)
        resolvedKeystoreAlias = intent?.getStringExtra(EXTRA_KEYSTORE_ALIAS).orEmpty()
        // A tap already in progress belongs to the challenge being replaced.
        supersedeInFlightApproval()
        val promptText = "$hostname is requesting sudo (peer_id ${shortPeerId(peerId)})"
        lastPromptText = promptText
        lastRenderedPeerId = peerId
        lastRenderedChallenge = resolvedChallenge
        stopCountdown()
        screen.value = ApprovalScreenState(promptText = promptText)
        startCountdown()
        Log.i(APPROVAL_LOG_TAG, "render peer=$peerId host=$hostname")
        return true
    }

    /**
     * Start the phone-side countdown for the challenge now on screen.
     *
     * It is the phone's own budget, not the desktop's: the desktop's deadline is
     * not in the frame, and a countdown that guessed it would be lying by however
     * much the two differ. What this clock promises is exactly what happens — the
     * prompt closes when it reaches zero, and answers nothing.
     */
    private fun startCountdown() {
        tickerJob = lifecycleScope.launch {
            while (true) {
                delay(APPROVAL_TICK_MILLIS)
                val current = screen.value
                if (!current.isOpen) {
                    return@launch
                }
                val next = current.afterTick()
                screen.value = next
                if (next.hasRunOut) {
                    onPromptExpired()
                    return@launch
                }
            }
        }
    }

    private fun stopCountdown() {
        tickerJob?.cancel()
        tickerJob = null
    }

    /**
     * The prompt ran out of time.
     *
     * Answers *nothing*: the all-zero frame means "the owner denied this" and is
     * not signature-checked (AUDIT-001 D-03), so writing it late would deny
     * whatever challenge is open by then. Closing the screen is the honest move —
     * the desktop's own deadline decides the authentication.
     */
    private fun onPromptExpired() {
        Log.i(APPROVAL_LOG_TAG, "prompt expired unanswered peer=$resolvedPeerId")
        approvalInFlight = false
        activeGate?.cancel()
        activeGate = null
        screen.value = screen.value.withOutcome(ApprovalOutcome.Denied("it expired — run the command again"))
        finishAfterDwell(DENIED_DWELL_MILLIS)
    }

    /** Finish after the verdict has been readable for [millis]. */
    private fun finishAfterDwell(millis: Long) {
        if (!dwellEnabled) {
            if (!isFinishing) finish()
            return
        }
        lifecycleScope.launch {
            delay(millis)
            if (!isFinishing) finish()
        }
    }

    /** True when the system asks for reduced motion. */
    private fun reduceMotion(): Boolean {
        val scale = android.provider.Settings.Global.getFloat(
            contentResolver,
            android.provider.Settings.Global.ANIMATOR_DURATION_SCALE,
            1f,
        )
        return scale == 0f
    }

    /** Test seam: invoked by the Compose Cancel button. */
    internal fun onCancelClicked() {
        Log.i(APPROVAL_LOG_TAG, "cancel peer=$resolvedPeerId reason=$DENIED_FRAME_REASON")
        stopCountdown()
        cancelSink?.onCancel(resolvedPeerId, DENIED_FRAME_BYTES)
        screen.value = screen.value.withOutcome(ApprovalOutcome.Denied("you cancelled it"))
        finish()
    }

    /**
     * Test seam: invoked by the Compose Approve button. S-015 wires
     * the [BiometricGate] + Keystore-sign + response-write path.
     * Each invocation produces exactly one BiometricPrompt round
     * (per-use Keystore key contract per SPEC §3.2 D6).
     */
    internal fun onApproveClicked() {
        val peerId = resolvedPeerId
        val alias = resolvedKeystoreAlias
        // The challenge is captured here, not read again inside the callback: an
        // approval answers the frame the operator was looking at when he tapped,
        // and a rebind in between must not silently re-target it (D-32).
        val challenge = resolvedChallenge
        val generation = approvalGeneration
        Log.i(APPROVAL_LOG_TAG, "approve peer=$peerId alias=$alias")
        // Test override on the companion seam takes precedence over
        // the per-instance production gate so a Robolectric JVM test
        // can drive succeed() / fail() without firing a real prompt.
        val gate = biometricGate ?: AndroidBiometricGate(
            activity = this,
            peerId = peerId,
            hostname = resolvedHostname,
        )
        activeGate = gate
        approvalInFlight = true
        gate.authenticate(
            alias,
            challenge,
            object : BiometricGateCallback {
                override fun onSucceeded(signatureBytes: ByteArray) {
                    if (!isStillTheOpenChallenge(generation, peerId)) return
                    Log.i(APPROVAL_LOG_TAG, "approve sig ok peer=$peerId len=${signatureBytes.size}")
                    answerAndAnnounce(ApprovalOutcome.Granted, signatureBytes, GRANTED_DWELL_MILLIS)
                }

                override fun onFailed(reason: String) {
                    if (!isStillTheOpenChallenge(generation, peerId)) return
                    Log.i(APPROVAL_LOG_TAG, "approve fail peer=$peerId reason=$reason")
                    answerAndAnnounce(
                        ApprovalOutcome.Denied(plainDenialReason(reason)),
                        DENIED_FRAME_BYTES,
                        DENIED_DWELL_MILLIS,
                    )
                }
            },
        )
    }

    /**
     * Drop the result of an approval whose challenge is no longer on screen.
     *
     * The prompt is withdrawn on rebind, but the OS may already have queued a
     * callback (a cancel arrives as `onAuthenticationError`). Writing that answer
     * would deny — or, worse, sign — a challenge nobody asked about.
     */
    private fun isStillTheOpenChallenge(generation: Int, peerId: String): Boolean {
        if (generation == approvalGeneration) {
            return true
        }
        Log.i(APPROVAL_LOG_TAG, "answer for a superseded challenge dropped peer=$peerId")
        return false
    }

    /**
     * Withdraw an approval that is running for the challenge being replaced.
     *
     * One biometric round signs one challenge — that rule does not bend when a
     * second challenge arrives mid-tap. The round is cancelled and the new
     * challenge is asked for afresh, so the operator's finger is not spent on a
     * prompt that no longer exists (AUDIT-001 D-32).
     */
    private fun supersedeInFlightApproval() {
        if (!approvalInFlight) {
            return
        }
        approvalInFlight = false
        approvalGeneration += 1
        activeGate?.cancel()
        activeGate = null
        Log.i(APPROVAL_LOG_TAG, "withdrew an in-flight approval for the superseded challenge")
    }

    private fun writeResponseAndFinish(responseBytes: ByteArray) {
        approvalInFlight = false
        activeGate = null
        responseSink?.onResponse(resolvedPeerId, responseBytes)
        if (!isFinishing) {
            finish()
        }
    }

    /**
     * Answer the challenge, then show the verdict for [dwellMillis] before closing.
     *
     * The answer goes first on purpose: the desktop is holding a password prompt
     * open, and the confirmation on the phone is for the operator, not for the
     * unlock. Nothing about the protocol waits for the animation.
     */
    private fun answerAndAnnounce(outcome: ApprovalOutcome, responseBytes: ByteArray, dwellMillis: Long) {
        approvalInFlight = false
        activeGate = null
        stopCountdown()
        responseSink?.onResponse(resolvedPeerId, responseBytes)
        screen.value = screen.value.withOutcome(outcome)
        finishAfterDwell(dwellMillis)
    }

    /**
     * Test helper exposing the constructed
     * `BiometricPrompt.PromptInfo` so the DoD assertion
     * `BiometricPromptTest::strong_authenticator_required` can pin
     * `allowedAuthenticators == BIOMETRIC_STRONG` without firing a
     * real prompt. Package-internal so production callers cannot
     * observe the prompt info.
     */
    internal fun buildPromptInfoForTest(): BiometricPrompt.PromptInfo =
        buildPromptInfo(this, resolvedHostname, shortPeerId(resolvedPeerId))

    public companion object {
        /**
         * Sink the activity calls on Cancel. Production sets this from
         * `MainActivity.installCompanionSeams`; tests inject a recording
         * fake. `@Volatile` because the activity (main thread) reads and
         * the service-side installer (binder thread) writes.
         */
        @Volatile
        public var cancelSink: CancelSink? = null

        /**
         * Sink the activity calls with the approve-side response
         * (signed bytes on success, [DENIED_FRAME_BYTES] on fail).
         * Production wires it to the same per-peer
         * `PersistentGattClient.writeResponse(...)` plumbing as
         * [cancelSink].
         */
        @Volatile
        public var responseSink: ResponseSink? = null

        /**
         * [BiometricGate] the activity routes Approve through.
         * Production sets this to [AndroidBiometricGate] in
         * `MainActivity.installCompanionSeams`; tests inject a
         * recording fake that drives `succeed(...)` / `fail(...)`
         * manually.
         */
        @Volatile
        public var biometricGate: BiometricGate? = null

        /** Reset all seams to `null`. Used by Robolectric tests. */
        /**
         * Whether a verdict is left on screen for its dwell before the activity
         * closes. Production: yes. Robolectric: the tests set this to `false`, so
         * "the activity finished" stays a synchronous assertion instead of a race
         * against a coroutine the JVM scheduler runs on its own clock.
         */
        @Volatile
        public var dwellEnabled: Boolean = true

        public fun resetSeams() {
            cancelSink = null
            responseSink = null
            biometricGate = null
            dwellEnabled = true
        }
    }
}

private fun shortPeerId(peerId: String): String =
    if (peerId.length <= SHORT_PEER_ID_LEN) peerId else peerId.substring(peerId.length - SHORT_PEER_ID_LEN)

/**
 * Build the `BiometricPrompt.PromptInfo` the activity hands to the
 * production [AndroidBiometricGate]. Pulled out as a top-level
 * helper so the unit test can pin
 * `allowedAuthenticators == BIOMETRIC_STRONG` without standing up a
 * real prompt.
 */
internal fun buildPromptInfo(
    activity: Activity,
    hostname: String,
    shortPeerId: String,
): BiometricPrompt.PromptInfo {
    val title = activity.getString(PROMPT_TITLE_RES)
    val subtitle = activity.getString(PROMPT_SUBTITLE_FMT, hostname, shortPeerId)
    val negative = activity.getString(PROMPT_NEGATIVE_RES)
    return BiometricPrompt.PromptInfo.Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setAllowedAuthenticators(STRONG_AUTHENTICATOR)
        .setNegativeButtonText(negative)
        .setConfirmationRequired(false)
        .build()
}

/**
 * Production [BiometricGate] backed by
 * `androidx.biometric:1.2.0-alpha05`'s `BiometricPrompt` and the
 * AndroidKeyStore-resident Ed25519 private key minted at pair time
 * by [com.sy.deunlock.android.pair.impl.AndroidKeystoreKeyGenerator]
 * (DEV-002).
 *
 * Each `authenticate(...)` call:
 *
 *   1. Opens the `PrivateKey` from `AndroidKeyStore` under
 *      [keystoreAlias].
 *   2. Builds a `Signature.getInstance("Ed25519")` and calls
 *      `initSign(privateKey)`.
 *   3. Wraps the `Signature` in a `BiometricPrompt.CryptoObject` so
 *      the OS gates the `sign()` call on a fresh biometric tap (the
 *      Keystore key was generated with
 *      `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`).
 *   4. Calls `prompt.authenticate(promptInfo, cryptoObject)`.
 *   5. On `onAuthenticationSucceeded`, calls
 *      `sig.update(challengeBytes); sig.sign()` and reports the
 *      bytes via `callback.onSucceeded(signatureBytes)`.
 *   6. On any error (cancel, lockout, hardware unavailable),
 *      reports via `callback.onFailed(reason)`.
 *
 * The class is `internal` because the only construction site is
 * the production wiring in `MainActivity.installCompanionSeams`;
 * tests use a recording fake `BiometricGate` instead.
 */
internal class AndroidBiometricGate(
    private val activity: FragmentActivity,
    private val peerId: String,
    private val hostname: String,
) : BiometricGate {

    /** The prompt currently open, so [cancel] has something to withdraw. */
    private var prompt: BiometricPrompt? = null

    override fun cancel() {
        val open = prompt ?: return
        prompt = null
        Log.i(APPROVAL_LOG_TAG, "withdrawing the biometric prompt peer=$peerId")
        runCatching { open.cancelAuthentication() }
    }

    override fun authenticate(
        keystoreAlias: String,
        challengeBytes: ByteArray,
        callback: BiometricGateCallback,
    ) {
        val privateKey = openPrivateKey(keystoreAlias)
        if (privateKey == null) {
            callback.onFailed("no PrivateKey under alias '$keystoreAlias'")
            return
        }
        // `initSign` on an AndroidKeyStore key throws
        // `KeyPermanentlyInvalidatedException` when biometrics or
        // device-credential enrollment changed since the key was
        // minted (`setInvalidatedByBiometricEnrollment(true)` is the
        // pairing-time contract). The key is unrecoverable by design;
        // delete the alias so the user gets pushed back through the
        // pairing flow, and surface a clean error to the activity
        // (which writes a denied frame) instead of crashing.
        val signature = runCatching {
            Signature.getInstance(ED25519_ALGORITHM).apply { initSign(privateKey) }
        }.getOrElse { err ->
            if (err is KeyPermanentlyInvalidatedException) {
                Log.w(
                    APPROVAL_LOG_TAG,
                    "key invalidated for peer=$peerId alias=$keystoreAlias — deleting and prompting re-pair",
                    err,
                )
                runCatching {
                    KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }.deleteEntry(keystoreAlias)
                }
                callback.onFailed("key invalidated; please re-pair on the desktop")
            } else {
                Log.w(APPROVAL_LOG_TAG, "initSign failed peer=$peerId", err)
                callback.onFailed("initSign failed: ${err.message}")
            }
            return
        }
        val executor = ContextCompat.getMainExecutor(activity)
        val authCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val sig = result.cryptoObject?.signature
                if (sig == null) {
                    callback.onFailed("crypto object missing signature")
                    return
                }
                val bytes = runCatching {
                    sig.update(challengeBytes)
                    sig.sign()
                }.getOrElse {
                    callback.onFailed("sign failed: ${it.message}")
                    return
                }
                callback.onSucceeded(bytes)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                callback.onFailed("[$errorCode] $errString")
            }

            override fun onAuthenticationFailed() {
                // Soft failure (bad fingerprint). The OS keeps the
                // prompt up; we do NOT route this to onFailed so the
                // user can retry until cancel/lockout fires
                // onAuthenticationError.
                Log.i(APPROVAL_LOG_TAG, "biometric soft-failed peer=$peerId; user can retry")
            }
        }
        val prompt = BiometricPrompt(activity, executor, authCallback)
        val promptInfo = buildPromptInfo(activity, hostname, shortPeerIdInternal(peerId))
        this.prompt = prompt
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }

    private fun openPrivateKey(alias: String): PrivateKey? {
        if (alias.isEmpty()) {
            return null
        }
        val keystore = runCatching {
            KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        }.getOrNull() ?: return null
        if (!keystore.containsAlias(alias)) {
            return null
        }
        return keystore.getKey(alias, null) as? PrivateKey
    }

    private fun shortPeerIdInternal(peerId: String): String = shortPeerId(peerId)
}

/** Title surfaced in the auth-screen TopAppBar; centralised so a future copy edit lands in one place. */
private const val APPROVAL_SCREEN_TITLE: String = "deunlock"

/** Outer screen padding. Matches `approve.ApproveScreen.SCREEN_PADDING_DP`. */
private val APPROVAL_PADDING_DP = 24.dp

/** Vertical gap between sections (icon → prompt → buttons). */
private val APPROVAL_SECTION_SPACING_DP = 16.dp

/** Vertical gap between the Approve and Cancel buttons. */
private val APPROVAL_BUTTON_SPACING_DP = 12.dp

/** Diameter of the countdown ring. Big enough to read from an arm's length. */
private val APPROVAL_RING_SIZE_DP = 200.dp

/** Ring stroke. Thick enough to see the arc shrink without looking for it. */
private val APPROVAL_RING_STROKE_DP = 10.dp

/** Seconds numeral inside the ring. */
private val APPROVAL_RING_NUMERAL_SP = 56.sp

/** Primary-button height; matches prrr-android's Connect button (56.dp). */
private val APPROVAL_BUTTON_HEIGHT_DP = 56.dp

/** Horizontal inset around the full-width Approve / Cancel buttons. */
private val APPROVAL_BUTTON_HORIZONTAL_PADDING_DP = 24.dp

/** Letter spacing on the terminal-style headline, so the caps read as a token. */
private const val APPROVAL_HEADLINE_TRACKING_EM: Float = 0.12f

/** Ring colour for a tone. Green is the app's accent, amber warns, red is the last chance. */
@Composable
private fun ringColour(state: ApprovalScreenState): Color = when (approvalTone(state)) {
    ApprovalTone.Calm -> SySuccess
    ApprovalTone.Warning -> SyWarning
    ApprovalTone.Urgent -> SyDanger
    ApprovalTone.Verdict -> if (state.outcome is ApprovalOutcome.Denied) SyDanger else SySuccess
}

/**
 * The prompt the operator sees over the keyguard.
 *
 * A countdown ring around the remaining seconds — the one number that matters
 * when the desktop is waiting — then the headline, the sentence naming the
 * computer and the request, and the two actions. On a verdict the ring and the
 * headline change colour and the buttons disappear, because the question is
 * already answered.
 *
 * @param reduceMotion system animation preference; the ring then renders as a
 *   static arc instead of an animated sweep.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ApprovalContent(
    state: ApprovalScreenState,
    reduceMotion: Boolean,
    onApprove: () -> Unit,
    onCancel: () -> Unit,
) {
    DeUnlockTheme {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(APPROVAL_SCREEN_TITLE) },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.background,
                        titleContentColor = MaterialTheme.colorScheme.onBackground,
                    ),
                )
            },
            containerColor = MaterialTheme.colorScheme.background,
        ) { paddingValues ->
            Surface(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues),
                color = MaterialTheme.colorScheme.background,
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(horizontal = APPROVAL_PADDING_DP),
                    verticalArrangement = Arrangement.Top,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Spacer(modifier = Modifier.height(APPROVAL_SECTION_SPACING_DP))
                    val accent = ringColour(state)
                    Box(
                        modifier = Modifier.size(APPROVAL_RING_SIZE_DP),
                        contentAlignment = Alignment.Center,
                    ) {
                        Canvas(modifier = Modifier.fillMaxSize()) {
                            val stroke = APPROVAL_RING_STROKE_DP.toPx()
                            val inset = stroke / 2f
                            val arcSize = Size(size.width - stroke, size.height - stroke)
                            drawArc(
                                color = SyBorder,
                                startAngle = RING_START_ANGLE,
                                sweepAngle = RING_FULL_SWEEP,
                                useCenter = false,
                                topLeft = Offset(inset, inset),
                                size = arcSize,
                                style = Stroke(width = stroke),
                            )
                            // A finished question keeps a full ring; a live one
                            // shrinks. With reduced motion asked for, the ring stays
                            // whole and only the numeral changes — the countdown is
                            // still readable, nothing moves under the operator.
                            val sweep = when {
                                !state.isOpen -> RING_FULL_SWEEP
                                reduceMotion -> RING_FULL_SWEEP
                                else -> RING_FULL_SWEEP * state.fractionRemaining
                            }
                            drawArc(
                                color = accent,
                                startAngle = RING_START_ANGLE,
                                sweepAngle = sweep,
                                useCenter = false,
                                topLeft = Offset(inset, inset),
                                size = arcSize,
                                style = Stroke(width = stroke, cap = StrokeCap.Round),
                            )
                        }
                        Text(
                            text = when (state.outcome) {
                                null -> state.remainingSeconds.toString()
                                ApprovalOutcome.Granted -> "OK"
                                is ApprovalOutcome.Denied -> "!"
                            },
                            color = accent,
                            fontSize = APPROVAL_RING_NUMERAL_SP,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.semantics {
                                testTag = APPROVAL_COUNTDOWN_TEST_TAG
                                contentDescription = if (state.isOpen) {
                                    "${state.remainingSeconds} seconds left"
                                } else {
                                    approvalHeadline(state)
                                }
                            },
                        )
                    }
                    Spacer(modifier = Modifier.height(APPROVAL_SECTION_SPACING_DP))
                    Text(
                        text = approvalHeadline(state),
                        color = accent,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = APPROVAL_HEADLINE_TRACKING_EM.em,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(modifier = Modifier.height(APPROVAL_SECTION_SPACING_DP))
                    Text(
                        text = state.promptText,
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onBackground,
                        textAlign = TextAlign.Center,
                    )
                    (state.outcome as? ApprovalOutcome.Denied)?.let { denied ->
                        Spacer(modifier = Modifier.height(APPROVAL_SECTION_SPACING_DP))
                        Text(
                            text = denied.reason,
                            style = MaterialTheme.typography.bodyMedium,
                            color = SyTextDim,
                            textAlign = TextAlign.Center,
                        )
                    }
                    Spacer(modifier = Modifier.weight(1f))
                    if (state.isOpen) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = APPROVAL_BUTTON_HORIZONTAL_PADDING_DP),
                            horizontalAlignment = Alignment.CenterHorizontally,
                        ) {
                            Button(
                                onClick = onApprove,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(APPROVAL_BUTTON_HEIGHT_DP),
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MaterialTheme.colorScheme.primary,
                                    contentColor = MaterialTheme.colorScheme.onPrimary,
                                ),
                            ) {
                                Text(
                                    text = "Approve",
                                    style = MaterialTheme.typography.titleMedium,
                                )
                            }
                            Spacer(modifier = Modifier.height(APPROVAL_BUTTON_SPACING_DP))
                            OutlinedButton(
                                onClick = onCancel,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(APPROVAL_BUTTON_HEIGHT_DP),
                                colors = ButtonDefaults.outlinedButtonColors(
                                    contentColor = MaterialTheme.colorScheme.error,
                                ),
                            ) {
                                Text(
                                    text = "Cancel",
                                    style = MaterialTheme.typography.titleMedium,
                                )
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(APPROVAL_SECTION_SPACING_DP))
                }
            }
        }
    }
}

/** Ring starts at twelve o'clock rather than three. */
private const val RING_START_ANGLE: Float = -90f

/** A full circle in degrees. */
private const val RING_FULL_SWEEP: Float = 360f

/** Test tag on the numeral inside the ring. */
internal const val APPROVAL_COUNTDOWN_TEST_TAG: String = "deunlock.approve.countdown"

/**
 * Build a fresh [Intent] that the production
 * `DeUnlockCompanionService.launchApprovalActivity` (and the future
 * direct caller) uses to start the activity with all the extras
 * S-015 needs. Centralised here so the test harness and the
 * production launch site share one builder.
 */
internal fun buildApprovalIntent(
    context: android.content.Context,
    peerId: String,
    hostname: String,
    challengeBytes: ByteArray,
    keystoreAlias: String,
): Intent = Intent(context, ChallengeApprovalActivity::class.java).apply {
    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    putExtra(EXTRA_PEER_ID, peerId)
    putExtra(EXTRA_HOSTNAME, hostname)
    putExtra(EXTRA_CHALLENGE_BYTES, challengeBytes)
    putExtra(EXTRA_KEYSTORE_ALIAS, keystoreAlias)
}
