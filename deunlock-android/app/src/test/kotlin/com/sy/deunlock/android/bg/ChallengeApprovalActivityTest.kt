// Roadmap item S-014 — Robolectric JVM tests for
// `ChallengeApprovalActivity`. Pins the DoD bullets from
// `specs/unlock-proximity/ROADMAP.md` Step S-014 verbatim:
//
//   1. `launches_over_keyguard` — boots the activity via
//      `Robolectric.buildActivity(...).create().start().resume()` and
//      asserts the package-internal `lastShowWhenLockedFlag` and
//      `lastTurnScreenOnFlag` recording fields both observe `true`
//      after `onCreate`.
//   2. `cancel_writes_denied_frame` — injects a recording
//      `CancelSink` seam on the companion object, calls
//      `activity.onCancelClicked()`, and asserts the sink received
//      exactly one call with `peerId` matching the fixture and bytes
//      equal to `DENIED_FRAME_BYTES`.
//   3. `hostname_shown_in_prompt` — reads the package-internal
//      `lastPromptText` recording field and asserts it equals
//      `"alex-desktop is requesting sudo (peer_id DD:EE:FF)"`.
//
// Journey: specs/journeys/JOURNEY-S-014-challenge-approval-activity.md
package com.sy.deunlock.android.bg

import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

private const val FIXTURE_HOSTNAME: String = "alex-desktop"
private const val FIXTURE_PEER_ID: String = "AA:BB:CC:DD:EE:FF"
private const val FIXTURE_CHALLENGE_LEN: Int = 33
private const val EXPECTED_PROMPT_TEXT: String =
    "alex-desktop is requesting sudo (peer_id DD:EE:FF)"

private const val SECOND_HOSTNAME: String = "other-desktop"
private const val SECOND_PEER_ID: String = "11:22:33:44:55:66"
private const val SECOND_CHALLENGE_SEED: Int = 7
private const val SECOND_EXPECTED_PROMPT_TEXT: String =
    "other-desktop is requesting sudo (peer_id 44:55:66)"

private class RecordingCancelSink : CancelSink {
    val calls: MutableList<Pair<String, ByteArray>> = mutableListOf()
    override fun onCancel(peerId: String, deniedFrameBytes: ByteArray) {
        calls += peerId to deniedFrameBytes
    }
}

private fun fixtureIntent(): Intent {
    val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    return Intent(context, ChallengeApprovalActivity::class.java).apply {
        putExtra(EXTRA_PEER_ID, FIXTURE_PEER_ID)
        putExtra(EXTRA_HOSTNAME, FIXTURE_HOSTNAME)
        putExtra(EXTRA_CHALLENGE_BYTES, ByteArray(FIXTURE_CHALLENGE_LEN) { it.toByte() })
    }
}

/** A challenge from a different desktop, delivered to an activity that is already up. */
private fun secondChallengeIntent(): Intent {
    val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    return Intent(context, ChallengeApprovalActivity::class.java).apply {
        putExtra(EXTRA_PEER_ID, SECOND_PEER_ID)
        putExtra(EXTRA_HOSTNAME, SECOND_HOSTNAME)
        putExtra(EXTRA_CHALLENGE_BYTES, ByteArray(FIXTURE_CHALLENGE_LEN) { (it + SECOND_CHALLENGE_SEED).toByte() })
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ChallengeApprovalActivityTest {

    @After
    fun cleanup() {
        ChallengeApprovalActivity.resetSeams()
    }

    @Test
    fun launches_over_keyguard() {
        val controller = Robolectric.buildActivity(
            ChallengeApprovalActivity::class.java,
            fixtureIntent(),
        ).create().start().resume()
        val activity = controller.get()

        assertTrue("setShowWhenLocked(true) called", activity.lastShowWhenLockedFlag)
        assertTrue("setTurnScreenOn(true) called", activity.lastTurnScreenOnFlag)
    }

    @Test
    fun cancel_writes_denied_frame() {
        val sink = RecordingCancelSink()
        ChallengeApprovalActivity.cancelSink = sink
        val controller = Robolectric.buildActivity(
            ChallengeApprovalActivity::class.java,
            fixtureIntent(),
        ).create().start().resume()
        val activity = controller.get()

        activity.onCancelClicked()

        assertEquals(1, sink.calls.size)
        assertEquals(FIXTURE_PEER_ID, sink.calls[0].first)
        assertArrayEquals(DENIED_FRAME_BYTES, sink.calls[0].second)
        assertTrue("activity is finishing after cancel", activity.isFinishing)
    }

    @Test
    fun hostname_shown_in_prompt() {
        val controller = Robolectric.buildActivity(
            ChallengeApprovalActivity::class.java,
            fixtureIntent(),
        ).create().start().resume()
        val activity = controller.get()

        assertEquals(EXPECTED_PROMPT_TEXT, activity.lastPromptText)
    }

    /**
     * D-31 — a second challenge that arrives while the prompt is already up must
     * replace it.
     *
     * The activity is `singleInstance` + `noHistory`: the second launch does not
     * create an instance, it delivers `onNewIntent` to the live one. Rendering
     * only in `onCreate` therefore left the *first* prompt on screen while the
     * desktop was already waiting on the second challenge — the operator
     * approved a frame nobody was waiting for, and the live challenge timed out.
     */
    @Test
    fun a_second_challenge_replaces_the_prompt() {
        val controller = Robolectric.buildActivity(
            ChallengeApprovalActivity::class.java,
            fixtureIntent(),
        ).create().start().resume()
        val activity = controller.get()
        assertEquals(EXPECTED_PROMPT_TEXT, activity.lastPromptText)

        controller.newIntent(secondChallengeIntent())

        assertEquals(
            "the live prompt must switch to the challenge that is actually open",
            SECOND_EXPECTED_PROMPT_TEXT,
            activity.lastPromptText,
        )
        assertEquals(SECOND_PEER_ID, activity.lastRenderedPeerId)
        assertArrayEquals(
            "the answer must be signed over the second challenge, not the first",
            ByteArray(FIXTURE_CHALLENGE_LEN) { (it + SECOND_CHALLENGE_SEED).toByte() },
            activity.lastRenderedChallenge,
        )
    }
}
