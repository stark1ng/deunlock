// Roadmap item S-017 — Approve screen Compose UI.
//
// Renders the in-app route that a notification tap lands on. The layout itself
// lives in `ApprovalSurface` (shared with the over-keyguard activity, so the
// operator sees one prompt rather than two): ring around the remaining seconds,
// terminal-style headline, the sentence naming the computer, and the two actions.
//
// This file owns only what is specific to the route: mapping the ViewModel's state
// onto an [ApprovalVisual], starting the countdown once, and dismissing after the
// verdict has been readable.
//
// The screen is a pure function of `ApproveUiState`. All side-effects (start the
// countdown, dispatch Approve, dispatch Deny) flow through the `ApproveViewModel`
// injected as a parameter.
package com.sy.deunlock.android.approve

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sy.deunlock.android.bg.ApprovalTone
import com.sy.deunlock.android.bg.URGENT_SECONDS
import com.sy.deunlock.android.bg.WARNING_SECONDS
import kotlinx.coroutines.delay

/** Maximum hostname length rendered. Excess is ellipsized. */
private const val HOSTNAME_MAX_CHARS: Int = 64

/** Title surfaced in the TopAppBar. Centralised so tests can assert on it. */
public const val APPROVE_SCREEN_TITLE: String = "deunlock"

/**
 * Dwell time on the `Approved` terminal state before the route dismisses itself.
 * Long enough that the user sees `ACCESS GRANTED` as confirmation, short enough
 * that it does not feel like a stall.
 */
public const val APPROVED_DISMISS_DELAY_MILLIS: Long = 1_200L

/**
 * Dwell time on the `Denied` terminal state. Longer than the approved dwell so the
 * user has time to read the reason before the route dismisses.
 */
public const val DENIED_DISMISS_DELAY_MILLIS: Long = 2_200L

/**
 * Render the Approve route for [viewModel]. When the state reaches a terminal
 * value, [onDismiss] is invoked after a short confirmation dwell so the host
 * activity can return to the previous foreground.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun ApproveScreen(
    viewModel: ApproveViewModel,
    onDismiss: () -> Unit = {},
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    // Start the countdown exactly once when the screen enters composition.
    LaunchedEffect(Unit) {
        viewModel.start()
    }

    // Auto-dismiss on a terminal state, once per transition: keying on the class
    // means a value change inside the same terminal variant would not restart the
    // timer.
    LaunchedEffect(state::class) {
        when (state) {
            is ApproveUiState.Approved -> {
                delay(APPROVED_DISMISS_DELAY_MILLIS)
                onDismiss()
            }
            is ApproveUiState.Denied -> {
                delay(DENIED_DISMISS_DELAY_MILLIS)
                onDismiss()
            }
            else -> Unit
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(APPROVE_SCREEN_TITLE) },
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
            ApprovalSurface(
                visual = state.toVisual(viewModel.hostname),
                approveEnabled = state is ApproveUiState.Counting,
                onApprove = viewModel::onApproveClicked,
                onDeny = viewModel::onDenyClicked,
                labels = ApprovalActionLabels(approve = "Approve", deny = "Deny"),
            )
        }
    }
}

/**
 * The ViewModel's state as something to draw.
 *
 * The countdown is the ViewModel's own budget (`DEFAULT_TIMEOUT_MILLIS`, 30 s) —
 * the same number the popup uses, so the ring means the same thing on both
 * surfaces.
 */
internal fun ApproveUiState.toVisual(hostname: String): ApprovalVisual {
    val safeHostname = sanitizeHostname(hostname)
    val requestLabel = (this as? ApproveUiState.Counting)?.requestLabel.orEmpty()
    val prompt = if (requestLabel.isEmpty()) {
        "Approve unlock for $safeHostname?"
    } else {
        "Approve unlock for $safeHostname?\n$requestLabel"
    }
    return when (this) {
        ApproveUiState.Idle -> ApprovalVisual(
            headline = "WAITING FOR YOU",
            prompt = prompt,
            secondsLeft = null,
            fractionRemaining = 1f,
            tone = ApprovalTone.Calm,
        )
        is ApproveUiState.Counting -> ApprovalVisual(
            headline = "WAITING FOR YOU",
            prompt = prompt,
            secondsLeft = remainingSeconds,
            fractionRemaining = remainingSeconds.toFloat() / DEFAULT_TIMEOUT_SECONDS,
            tone = when {
                remainingSeconds <= URGENT_SECONDS -> ApprovalTone.Urgent
                remainingSeconds <= WARNING_SECONDS -> ApprovalTone.Warning
                else -> ApprovalTone.Calm
            },
        )
        ApproveUiState.AwaitingBiometric -> stepVisual(prompt, "touch the sensor", "SENSOR OPEN")
        ApproveUiState.Signing -> stepVisual(prompt, "signing on the phone", "SIGNING")
        is ApproveUiState.Approved -> ApprovalVisual(
            headline = "ACCESS GRANTED",
            prompt = prompt,
            secondsLeft = null,
            fractionRemaining = 1f,
            tone = ApprovalTone.Verdict,
            actionsVisible = false,
        )
        is ApproveUiState.Denied -> ApprovalVisual(
            headline = "DENIED",
            prompt = prompt,
            secondsLeft = null,
            fractionRemaining = 1f,
            tone = ApprovalTone.Verdict,
            detail = denialReasonLabel(reason),
            actionsVisible = false,
        )
    }
}

/** A step between tapping and the verdict: no countdown, no actions, one line of what is happening. */
private fun stepVisual(prompt: String, detail: String, headline: String): ApprovalVisual =
    ApprovalVisual(
        headline = headline,
        prompt = prompt,
        secondsLeft = null,
        fractionRemaining = 1f,
        tone = ApprovalTone.Calm,
        detail = detail,
        actionsVisible = false,
    )

/** Seconds the ViewModel's countdown starts from, for the ring's fraction. */
private const val DEFAULT_TIMEOUT_SECONDS: Float = DEFAULT_TIMEOUT_MILLIS / 1_000f

private fun denialReasonLabel(reason: DenialReason): String = when (reason) {
    DenialReason.UserDenied -> "you denied it"
    DenialReason.TimedOut -> "it expired — run the command again"
    DenialReason.BiometricFailed -> "the sensor did not recognise you"
    DenialReason.BiometricUnavailable -> "no fingerprint enrolled on this phone"
    is DenialReason.SignError -> "the phone could not sign — try again (${reason.reason})"
}

/**
 * Cap the hostname at [HOSTNAME_MAX_CHARS] characters and strip
 * newlines so an attacker-controlled name cannot inject a multi-line
 * phishing prompt. Defends T-014 (biometric coercion / phishing).
 */
internal fun sanitizeHostname(raw: String): String {
    val singleLine = raw.replace('\n', ' ').replace('\r', ' ')
    return if (singleLine.length > HOSTNAME_MAX_CHARS) {
        singleLine.substring(0, HOSTNAME_MAX_CHARS) + "…"
    } else {
        singleLine
    }
}
