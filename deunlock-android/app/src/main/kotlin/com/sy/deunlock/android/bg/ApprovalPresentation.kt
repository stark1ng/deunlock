// W-3 — what the approval prompt shows, kept separate from how it draws it.
//
// The popup is the surface the operator meets every hour, and it had no sense of
// time: a challenge that had already expired on the desktop sat on the phone
// until somebody cleared it (AUDIT-001 D-27, phone half). Two numbers make that
// honest:
//
//   * the phone's own budget — the prompt closes itself when it runs out, and
//     answers nothing, because a late "deny" would cancel a *newer* challenge
//     (the all-zero frame is a deliberate denial and is not signature-checked);
//   * the dwell on a terminal state — long enough to read the verdict, short
//     enough not to feel like a stall.
//
// Everything here is pure so the states can be tested without Compose, a
// Robolectric clock, or a real sensor.
package com.sy.deunlock.android.bg

import kotlin.math.ceil

/**
 * How long the prompt stays up before closing itself.
 *
 * The desktop's window is 25 s (`pam_deunlock.so timeout=25000` /
 * `choice=25000`), and the phone's own approval model counts down from 30 s
 * (`approve.DEFAULT_TIMEOUT_MILLIS`). Thirty seconds here means the prompt never
 * outlives the question it is asking by more than five.
 */
public const val APPROVAL_BUDGET_MILLIS: Long = 30_000L

/** Countdown cadence: one second is what a human reads as a countdown. */
public const val APPROVAL_TICK_MILLIS: Long = 1_000L

/** Time the "ACCESS GRANTED" verdict stays on screen before the popup closes. */
public const val GRANTED_DWELL_MILLIS: Long = 1_200L

/** Time the "DENIED" verdict stays on screen — longer, because there is a reason to read. */
public const val DENIED_DWELL_MILLIS: Long = 2_200L

/** How the question ended, when it has. `null` in [ApprovalScreenState.outcome] means it is still open. */
public sealed class ApprovalOutcome {
    public data object Granted : ApprovalOutcome()
    public data class Denied(val reason: String) : ApprovalOutcome()
}

/**
 * Everything the prompt draws, in one value.
 *
 * @param promptText the sentence naming the computer and the request.
 * @param remainingMillis budget still available, in milliseconds.
 * @param budgetMillis the budget the prompt started with, for the ring fraction.
 * @param outcome `null` while the question is open.
 */
public data class ApprovalScreenState(
    val promptText: String,
    val remainingMillis: Long = APPROVAL_BUDGET_MILLIS,
    val budgetMillis: Long = APPROVAL_BUDGET_MILLIS,
    val outcome: ApprovalOutcome? = null,
) {
    /** Seconds left, rounded up so the display reaches 0 only when time is up. */
    public val remainingSeconds: Int
        get() = ceil(remainingMillis.coerceAtLeast(0).toDouble() / 1_000.0).toInt()

    /** Share of the budget left, 1.0 down to 0.0 — the ring's arc length. */
    public val fractionRemaining: Float
        get() = if (budgetMillis <= 0) 0f else (remainingMillis.coerceAtLeast(0).toFloat() / budgetMillis.toFloat()).coerceIn(0f, 1f)

    /** True while the question is still open. */
    public val isOpen: Boolean
        get() = outcome == null

    /** The budget is spent and nothing has been answered. */
    public val hasRunOut: Boolean
        get() = outcome == null && remainingMillis <= 0

    /** One tick of the countdown; stops at zero rather than going negative. */
    public fun afterTick(): ApprovalScreenState =
        if (!isOpen) this else copy(remainingMillis = (remainingMillis - APPROVAL_TICK_MILLIS).coerceAtLeast(0))

    /** Close the question with a verdict. */
    public fun withOutcome(outcome: ApprovalOutcome): ApprovalScreenState = copy(outcome = outcome)
}

/**
 * The verdict headline, in the terminal voice the rest of the app uses.
 *
 * Deliberately not localised: it is a status token, not a sentence, and the
 * operator reads it the same way in every language.
 */
public fun approvalHeadline(state: ApprovalScreenState): String = when (state.outcome) {
    null -> "WAITING FOR YOU"
    ApprovalOutcome.Granted -> "ACCESS GRANTED"
    is ApprovalOutcome.Denied -> "DENIED"
}

/**
 * A biometric or signer failure, in words a person can act on.
 *
 * The raw reasons come from `androidx.biometric` (`"[5] Canceled"`), from the
 * Keystore (`"no PrivateKey under alias …"`) and from our own signer. None of
 * them is a sentence, and the operator sees this line exactly once per failure.
 */
public fun plainDenialReason(raw: String): String {
    val lower = raw.lowercase()
    return when {
        lower.contains("cancel") || lower.contains("declined") -> "you cancelled it"
        lower.contains("no privatekey") || lower.contains("key invalidated") || lower.contains("re-pair") ->
            "the key is gone — pair this phone again"
        lower.contains("no biometric") || lower.contains("not enrolled") || lower.contains("unavailable") ->
            "no fingerprint enrolled on this phone"
        lower.contains("lockout") -> "too many attempts — try the password"
        lower.contains("initSign".lowercase()) || lower.contains("sign failed") -> "the phone could not sign — try again"
        else -> "the sensor refused"
    }
}

/** Which accent the countdown ring uses. */
public enum class ApprovalTone {
    /** Plenty of time. */
    Calm,

    /** Under ten seconds. */
    Warning,

    /** Under three seconds — the last chance to reach the sensor. */
    Urgent,

    /** The question is answered. */
    Verdict,
}

/** Seconds left at which the ring turns amber. */
public const val WARNING_SECONDS: Int = 10

/** Seconds left at which the ring turns red. */
public const val URGENT_SECONDS: Int = 3

/**
 * The ring colour, as a decision rather than a colour.
 *
 * Kept here so the thresholds are testable and the composable only maps a tone
 * onto the theme's palette.
 */
public fun approvalTone(state: ApprovalScreenState): ApprovalTone = when {
    !state.isOpen -> ApprovalTone.Verdict
    state.remainingSeconds <= URGENT_SECONDS -> ApprovalTone.Urgent
    state.remainingSeconds <= WARNING_SECONDS -> ApprovalTone.Warning
    else -> ApprovalTone.Calm
}
