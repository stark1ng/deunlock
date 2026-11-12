// W-3 — one prompt, two surfaces.
//
// The phone shows an approval prompt twice over: as a full-screen activity over
// the keyguard when a challenge arrives, and as a route inside the app when the
// operator taps the notification. They had drifted into two different layouts for
// the same question, which is exactly the kind of drift the project's own rule
// forbids — the operator should recognise the thing asking for his finger.
//
// So both build an [ApprovalVisual] and render it here: ring around the seconds,
// terminal-style headline, the sentence naming the computer, the reason when it
// was refused, and the two actions while the question is open.
package com.sy.deunlock.android.approve

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import com.sy.deunlock.android.bg.ApprovalTone
import com.sy.deunlock.android.ui.theme.SyBorder
import com.sy.deunlock.android.ui.theme.SyDanger
import com.sy.deunlock.android.ui.theme.SySuccess
import com.sy.deunlock.android.ui.theme.SyTextDim
import com.sy.deunlock.android.ui.theme.SyWarning

/** Test tags shared by both surfaces, so one harness can drive either. */
public object ApproveScreenTestTags {
    public const val HOSTNAME: String = "deunlock.approve.hostname"
    public const val APPROVE_BUTTON: String = "deunlock.approve.approve_button"
    public const val DENY_BUTTON: String = "deunlock.approve.deny_button"
    public const val COUNTDOWN: String = "deunlock.approve.countdown"
    public const val TERMINAL: String = "deunlock.approve.terminal"
}

/**
 * Everything the prompt draws, independent of which state machine produced it.
 *
 * @param headline the terminal-style line: `WAITING FOR YOU`, `ACCESS GRANTED`, `DENIED`, …
 * @param prompt the sentence naming the computer and the request.
 * @param secondsLeft `null` when there is nothing to count (a verdict, or a step
 *   that is not a countdown).
 * @param fractionRemaining share of the budget left, for the ring.
 * @param tone which accent the ring and headline use.
 * @param detail a second line under the prompt — the denial reason, or the step.
 * @param actionsVisible whether the two buttons belong on screen.
 */
public data class ApprovalVisual(
    val headline: String,
    val prompt: String,
    val secondsLeft: Int?,
    val fractionRemaining: Float,
    val tone: ApprovalTone,
    val detail: String? = null,
    val actionsVisible: Boolean = true,
)

/** Labels on the two actions; the popup says Cancel, the in-app route says Deny. */
public data class ApprovalActionLabels(
    val approve: String = "Approve",
    val deny: String = "Deny",
)

/** Ring starts at twelve o'clock rather than three. */
private const val RING_START_ANGLE: Float = -90f

/** A full circle in degrees. */
private const val RING_FULL_SWEEP: Float = 360f

/** Diameter of the countdown ring. */
private val RING_SIZE_DP = 200.dp

/** Ring stroke: thick enough to see the arc shrink without hunting for it. */
private val RING_STROKE_DP = 10.dp

/** Numerals inside the ring. */
private val RING_NUMERAL_SP = 56.sp

/** Vertical rhythm between sections. */
private val SECTION_SPACING_DP = 16.dp

/** Height of both action buttons. */
private val BUTTON_HEIGHT_DP = 56.dp

/** Gap between the two buttons. */
private val BUTTON_SPACING_DP = 12.dp

/** Horizontal inset around the buttons. */
private val BUTTON_HORIZONTAL_PADDING_DP = 24.dp

/** Letter spacing that makes the caps read as a token rather than a word. */
private const val HEADLINE_TRACKING_EM: Float = 0.12f

/** Ring colour for a tone. */
@Composable
private fun toneColour(visual: ApprovalVisual): Color = when (visual.tone) {
    ApprovalTone.Calm -> SySuccess
    ApprovalTone.Warning -> SyWarning
    ApprovalTone.Urgent -> SyDanger
    ApprovalTone.Verdict -> if (visual.headline == "DENIED") SyDanger else SySuccess
}

/**
 * Render [visual]. A pure function of its argument — no timers, no state — so
 * both surfaces can hand it whatever their own machine computed.
 */
@Composable
public fun ApprovalSurface(
    visual: ApprovalVisual,
    approveEnabled: Boolean,
    onApprove: () -> Unit,
    onDeny: () -> Unit,
    reduceMotion: Boolean = false,
    labels: ApprovalActionLabels = ApprovalActionLabels(),
) {
    val accent = toneColour(visual)
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = BUTTON_HORIZONTAL_PADDING_DP),
        verticalArrangement = Arrangement.Top,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(modifier = Modifier.height(SECTION_SPACING_DP))
        Box(
            modifier = Modifier.size(RING_SIZE_DP),
            contentAlignment = Alignment.Center,
        ) {
            Canvas(modifier = Modifier.fillMaxSize()) {
                val stroke = RING_STROKE_DP.toPx()
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
                // Reduced motion keeps the ring whole and lets only the numeral
                // change; the countdown is still readable, nothing moves.
                val sweep = when {
                    visual.secondsLeft == null -> RING_FULL_SWEEP
                    reduceMotion -> RING_FULL_SWEEP
                    else -> RING_FULL_SWEEP * visual.fractionRemaining.coerceIn(0f, 1f)
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
                text = when {
                    visual.secondsLeft != null -> visual.secondsLeft.toString()
                    visual.headline == "ACCESS GRANTED" -> "OK"
                    visual.headline.startsWith("DENIED") -> "!"
                    else -> "…"
                },
                color = accent,
                fontSize = RING_NUMERAL_SP,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.semantics {
                    testTag = ApproveScreenTestTags.COUNTDOWN
                    contentDescription = visual.secondsLeft?.let { "$it seconds left" } ?: visual.headline
                },
            )
        }
        Spacer(modifier = Modifier.height(SECTION_SPACING_DP))
        Text(
            text = visual.headline,
            color = accent,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            letterSpacing = HEADLINE_TRACKING_EM.em,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { testTag = ApproveScreenTestTags.TERMINAL },
        )
        Spacer(modifier = Modifier.height(SECTION_SPACING_DP))
        Text(
            text = visual.prompt,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center,
            modifier = Modifier.semantics { testTag = ApproveScreenTestTags.HOSTNAME },
        )
        visual.detail?.let { detail ->
            Spacer(modifier = Modifier.height(SECTION_SPACING_DP))
            Text(
                text = detail,
                style = MaterialTheme.typography.bodyMedium,
                color = SyTextDim,
                textAlign = TextAlign.Center,
            )
        }
        Spacer(modifier = Modifier.weight(1f))
        if (visual.actionsVisible) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Button(
                    onClick = onApprove,
                    enabled = approveEnabled,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(BUTTON_HEIGHT_DP)
                        .semantics { testTag = ApproveScreenTestTags.APPROVE_BUTTON },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    ),
                ) {
                    Text(text = labels.approve, style = MaterialTheme.typography.titleMedium)
                }
                Spacer(modifier = Modifier.height(BUTTON_SPACING_DP))
                OutlinedButton(
                    onClick = onDeny,
                    enabled = approveEnabled,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(BUTTON_HEIGHT_DP)
                        .semantics { testTag = ApproveScreenTestTags.DENY_BUTTON },
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Text(text = labels.deny, style = MaterialTheme.typography.titleMedium)
                }
            }
        }
        Spacer(modifier = Modifier.height(SECTION_SPACING_DP))
    }
}
