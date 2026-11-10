# Glossary

| Term | Meaning in deunlock |
| --- | --- |
| Application bond | deunlock's stored peer identity, public key, and application bond material; distinct from an OS Bluetooth bond |
| Biometric strong | Android's Class 3 biometric authentication required by the active signing prompt |
| BLE | Bluetooth Low Energy, the transport for pairing and unlock messages |
| Bond key | The application's 32-byte derivation output from exchanged public keys; the name does not imply a confidential key agreement |
| CCCD | Client Characteristic Configuration Descriptor; Android writes it to subscribe to challenge notifications |
| CDM | Android CompanionDeviceManager; records a companion association and supports background presence handling |
| Challenge body | Version, fresh nonce, and payload bytes; the phone signs this body, excluding the trailing MAC |
| GATT central / client | Android's role: connect, discover services, subscribe, and write responses |
| GATT peripheral / server | Linux's role: advertise and expose pairing and unlock characteristics |
| Keystore alias | Identifier used to access the phone's signing key without exporting its private bytes |
| LESC | Bluetooth LE Secure Connections; pairing includes numeric comparison on both devices |
| MAC | Message authentication code; deunlock's frame helper uses truncated keyed BLAKE3 |
| Nonce | Fresh 16-byte random challenge value that binds a signature to one request |
| OOB code | Application-level four-word code compared separately from Bluetooth's six-digit code |
| PAM | Linux Pluggable Authentication Modules; the service's stack combines module results into an access decision |
| Peer ID | Identifier of an application bond; use the exact ID printed by `deunlock list` for CLI revocation |
| Presenced | `deunlock-presenced`, the desktop user daemon that owns BLE and verifies phone responses |
| Replay | Reuse of an earlier response; fresh challenge bodies and the daemon's recent-nonce cache constrain acceptance |
| Session UUID | Rotating advertised rendezvous value derived from application bond material and a minute counter |
| StrongBox | Optional Android isolated security hardware; requested during key generation with a Keystore fallback |

<!-- Structure: Good Docs Project glossary; original prose for deunlock. -->
