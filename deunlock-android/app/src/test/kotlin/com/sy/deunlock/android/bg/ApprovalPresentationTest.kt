// W-3 — the countdown and the verdict copy, without a screen.
//
// The interesting behaviour of the prompt is arithmetic and mapping, so it is
// tested here rather than through Compose: the ring must reach 0 exactly when the
// budget is spent, a verdict must freeze the countdown, and every raw sensor
// string the platform can hand us must turn into words a person can act on.
package com.sy.deunlock.android.bg

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private const val PROMPT = "deunlock is requesting sudo (peer_id 04:EA:56)"

class ApprovalPresentationTest {

    @Test
    fun the_countdown_starts_at_the_whole_budget() {
        val state = ApprovalScreenState(promptText = PROMPT)
        assertEquals(30, state.remainingSeconds)
        assertEquals(1f, state.fractionRemaining, 0.0001f)
        assertTrue(state.isOpen)
    }

    @Test
    fun a_partial_second_still_reads_as_a_second() {
        val state = ApprovalScreenState(promptText = PROMPT, remainingMillis = 1_001)
        assertEquals("a prompt that has 1.001 s left must not read as 1 s and then jump", 2, state.remainingSeconds)
        assertEquals(0, ApprovalScreenState(promptText = PROMPT, remainingMillis = 0).remainingSeconds)
    }

    @Test
    fun the_countdown_stops_at_zero_and_reports_running_out() {
        var state = ApprovalScreenState(promptText = PROMPT, remainingMillis = 1_500)
        assertFalse(state.hasRunOut)
        state = state.afterTick()
        assertEquals(500, state.remainingMillis)
        assertFalse("half a second left is not yet out of time", state.hasRunOut)
        state = state.afterTick()
        assertEquals(0, state.remainingMillis)
        assertTrue(state.hasRunOut)
        assertEquals("and it does not go negative", 0, state.afterTick().remainingMillis)
    }

    @Test
    fun a_verdict_freezes_the_countdown() {
        val granted = ApprovalScreenState(promptText = PROMPT).withOutcome(ApprovalOutcome.Granted)
        assertFalse(granted.isOpen)
        assertFalse("a verdict is not a timeout", granted.hasRunOut)
        assertEquals(granted, granted.afterTick())
        assertEquals("ACCESS GRANTED", approvalHeadline(granted))
    }

    @Test
    fun the_ring_shrinks_with_the_budget() {
        val half = ApprovalScreenState(promptText = PROMPT, remainingMillis = 15_000)
        assertEquals(0.5f, half.fractionRemaining, 0.0001f)
        val empty = ApprovalScreenState(promptText = PROMPT, remainingMillis = 0)
        assertEquals(0f, empty.fractionRemaining, 0.0001f)
    }

    @Test
    fun a_zero_budget_never_divides_by_zero() {
        val state = ApprovalScreenState(promptText = PROMPT, remainingMillis = 0, budgetMillis = 0)
        assertEquals(0f, state.fractionRemaining, 0.0001f)
    }

    @Test
    fun the_headline_names_the_state() {
        assertEquals("WAITING FOR YOU", approvalHeadline(ApprovalScreenState(promptText = PROMPT)))
        assertEquals(
            "DENIED",
            approvalHeadline(
                ApprovalScreenState(promptText = PROMPT).withOutcome(ApprovalOutcome.Denied("you cancelled it")),
            ),
        )
    }

    @Test
    fun every_raw_sensor_string_becomes_words() {
        assertEquals("you cancelled it", plainDenialReason("[5] Canceled"))
        assertEquals("you cancelled it", plainDenialReason("user declined"))
        assertEquals(
            "the key is gone — pair this phone again",
            plainDenialReason("no PrivateKey under alias 'deunlock.ed25519.04EA'"),
        )
        assertEquals(
            "the key is gone — pair this phone again",
            plainDenialReason("key invalidated; please re-pair on the desktop"),
        )
        assertEquals(
            "no fingerprint enrolled on this phone",
            plainDenialReason("[12] No biometrics enrolled"),
        )
        assertEquals("too many attempts — try the password", plainDenialReason("[9] Lockout"))
        assertEquals("the phone could not sign — try again", plainDenialReason("initSign failed: key invalid"))
        assertEquals("the sensor refused", plainDenialReason("something entirely new"))
    }

    @Test
    fun the_ring_warns_before_it_is_too_late() {
        val calm = ApprovalScreenState(promptText = PROMPT, remainingMillis = 25_000)
        assertEquals(ApprovalTone.Calm, approvalTone(calm))
        val warning = ApprovalScreenState(promptText = PROMPT, remainingMillis = 10_000)
        assertEquals("ten seconds left is already a warning", ApprovalTone.Warning, approvalTone(warning))
        val urgent = ApprovalScreenState(promptText = PROMPT, remainingMillis = 3_000)
        assertEquals(ApprovalTone.Urgent, approvalTone(urgent))
        val answered = urgent.withOutcome(ApprovalOutcome.Granted)
        assertEquals("a verdict overrides the countdown", ApprovalTone.Verdict, approvalTone(answered))
    }
}
