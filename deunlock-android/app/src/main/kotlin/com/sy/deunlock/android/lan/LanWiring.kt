package com.sy.deunlock.android.lan

import uniffi.deunlock_mobile.FrameSigner
import uniffi.deunlock_mobile.buildLanHello
import uniffi.deunlock_mobile.buildResponseSignature

/**
 * Wires [LanClient] to the Rust core, so the Wi-Fi path and the BLE path share
 * one implementation of the protocol:
 *
 * - the hello is encoded by `buildLanHello`, the same function the desktop's
 *   verifier is tested against;
 * - the challenge is verified (MAC) and signed by `buildResponseSignature`, which
 *   signs the transcript — never a hand-rolled layout here.
 *
 * The bond key exists only as bytes in this JVM; the Ed25519 private key stays in
 * the Keystore behind [FrameSigner].
 */
public object LanWiring {

    /** Build a client for one paired desktop. */
    public fun client(
        endpoint: LanEndpoint,
        bondKey: ByteArray,
        hostId: ByteArray,
        peerId: ByteArray,
        frameSigner: FrameSigner,
    ): LanClient = LanClient(
        endpoint = endpoint,
        helloBuilder = { sessionNonce ->
            buildLanHello(bondKey, hostId, peerId, sessionNonce)
        },
        signChallenge = { challengeFrame ->
            buildResponseSignature(bondKey, frameSigner, challengeFrame)
        },
    )
}
