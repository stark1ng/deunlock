# Your first phone approval

In this tutorial, you authenticate a `sudo` request with your phone and verify that PAM used deunlock.

## Prerequisites

You need a desktop and phone configured through [installation](../how-to/install.md) and [pairing](../how-to/pair-and-revoke.md). Your administrator must have enabled deunlock for `sudo`, with a working recovery method. Keep the administrator session used for setup open.

Have your phone nearby, with Bluetooth enabled and a strong biometric enrolled. Confirm that `systemctl --user is-active deunlock-presenced` prints `active` and `deunlock list` shows an active bond.

## Request authentication

Expire your cached sudo authorization, then ask sudo to authenticate:

```sh
sudo -k
sudo -v
```

The phone should show an approval request naming your bonded computer. A cached sudo authorization would skip PAM, which is why the first command matters.

## Approve on your phone

Check the computer name, tap **Approve**, and complete the strong biometric prompt. Approve only the request you just initiated. The phone signs the challenge inside Android Keystore and sends the signature back over BLE.

If the approval screen does not appear, return to the desktop's existing authentication method, then follow [troubleshooting](../how-to/troubleshoot.md).

## Verify the result

`sudo -v` should exit successfully. A successful command alone does not identify the authentication method: inspect the service's authentication log for `grantors=pam_deunlock`, where your distribution supplies that field, or inspect the daemon transaction for `outcome=ok`:

```sh
journalctl --user -u deunlock-presenced -n 30 --no-pager
deunlock status --json
```

Correlate the daemon transaction with your request. The status timestamps are not proof that Bluetooth is subscribed: `last_connect_ms_ago` currently records challenge activity.

## Next steps

Watch [the unlock exchange](../explanation/mechanics.md#unlock-a-fresh-signature-for-each-request), learn how to [revoke a phone](../how-to/pair-and-revoke.md#revoke-a-phone), or look up [failure results](../reference/protocol.md#results-returned-to-pam).

<!-- Structure: Good Docs Project tutorial; original prose for deunlock. -->
