# Pair or revoke a phone

Pairing records the phone's public signing key and the application bond material. A Bluetooth system bond alone does not authorize deunlock unlocks.

## Pair a phone

You need the [installed daemon and companion app](install.md), Bluetooth enabled on both devices, and permission to write the desktop bond store. Use your desktop account's terminal so the CLI can reach its daemon socket.

1. Start the desktop pairing window:

    ```sh
    deunlock pair --adapter hci0
    ```

2. On Android, choose **Pair with computer** and select the intended desktop in the system device picker.
3. Compare the **six-digit Bluetooth code** on both devices. Confirm on both. In terminal mode, type `y` and press Enter at the desktop prompt. If the codes differ, cancel.
4. Compare the **four-word application code** displayed by deunlock on both devices. This is a separate confirmation. Accept it only if it matches.
5. Finish the companion-device and background setup prompts, then return to the home screen.

Verify the result:

```sh
deunlock list
deunlock status --json
```

The desktop should contain an active bond. For connection readiness, look for the phone's successful notification descriptor write and the desktop's `phone subscribed` log; a bond record by itself does not establish a live connection.

If your desktop uses the sy Waybar applet, `deunlock pair --waybar` moves the Bluetooth numeric-confirmation decision to the bar. The four-word confirmation still belongs to the application pairing flow. Avoid `--yes` for interactive pairing because it skips confirmation prompts.

## Re-pair an existing record

If the CLI reports that the phone is already bonded, decide whether to retain or replace that record. `deunlock pair --force` permits replacing the desktop application record for that peer; it does not clear the OS Bluetooth bond. Re-pair after a phone reset or lost Keystore key, rather than copying private key material between phones.

Returning into Bluetooth range normally uses the existing bond. Do not re-pair to repair a temporary disconnect; follow [connection troubleshooting](troubleshoot.md#the-phone-is-bonded-but-does-not-receive-requests).

## Revoke a phone

Find the peer ID, then revoke the application bond:

```sh
deunlock list
deunlock revoke --id <peer_id> --reason "phone replaced"
```

Replace `<peer_id>` with the ID printed by `list`. Revocation is idempotent and retains the record for history. Check that `list` reports it as revoked and `status --json` no longer lists it as an active daemon peer after reload.

Remove the companion association and Bluetooth system bond on the phone if you are retiring it. Those OS records are distinct from the application bond. Confirm your desktop's alternative authentication method works before removing your only phone.

See [the pairing mechanics](../explanation/mechanics.md#pairing-establish-the-phone-identity) for the key exchange order and the two confirmations.

<!-- Structure: Diátaxis how-to; original prose for deunlock. -->
