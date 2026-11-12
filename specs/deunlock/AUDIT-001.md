# AUDIT-001 — крипто и PAM-семантика DoUnlock v0.3.0

Дата: 2026-11-10. База: syauth v0.3.0 (MIT), форк `deunlock`.
Метод: чтение кода + сверка с `docs/reference/protocol.md` и `specs/threat/THREAT-2026-05-15.md`.
Статус: находки подтверждены по коду, кроме помеченных «по документации».

## Сводка

| ID | Severity | Суть | Статус |
|----|----------|------|--------|
| D-01 | high | `bond_key` выводится только из публичных ключей — это не секрет | подтверждено |
| D-02 | medium | телефон не аутентифицирует десктоп; MAC челленджа не проверяется на телефоне | подтверждено |
| D-03 | medium | отказ на телефоне маппится в `PAM_AUTH_ERR` → при `required` пропадает fallback на пароль | подтверждено |
| D-04 | medium | PAM-модуль не проверяет `ok`/наличие подписи/nonce — только строку `reason` | по документации + auth.rs |
| D-05 | medium | нет шифрования канала и forward secrecy | подтверждено |
| D-06 | low | челлендж не привязан к сервису/пользователю | подтверждено |
| D-07 | low | пейринг опирается на numeric compare + 4 эмодзи вместо QR-связывания | подтверждено |

## D-01 — bond_key не является секретом (high)

`crates/deunlock-core/src/bond.rs:288`:

```rust
ikm = host_pubkey || phone_pubkey;            // ОБА — публичные ключи
bond_key = HKDF-SHA256(None, ikm, "deunlock-bond-v1", 32)
```

Комментарий в коде (`bond.rs:270-274`) утверждает, что LESC-линк гарантирует
незаурядность входов. Это неверно: входы — публичные ключи Ed25519, они
передаются по GATT-характеристикам пейринга (`5a4e8e3c-…-0102/0103`) и лежат в
bond store на телефоне. Любой, кто один раз увидел оба ключа, вычисляет
`bond_key` локально.

Следствия:

1. `compute_tag` (`crates/deunlock-core/src/mac.rs:42`) ключуется публично
   выводимым значением → MAC челленджа не аутентифицирует ничего.
2. Ротация рекламного UUID `HKDF(bond_key, "…session-v1" || minute)`
   (`crates/deunlock-transport/src/bluez.rs`) реверсивна для того, кто видел
   пейринг, — заявленное в THREAT §4.9 свойство «unlinkable across minutes»
   держится только против наблюдателя, пропустившего пейринг.
3. Телефон не может отличить настоящий десктоп от чужого BLE-периферийного
   устройства, потому что проверять ему нечего.

**Исправление (v2 протокола).** ECDH P-256 на пейринге: телефон генерирует
EC-ключ в Android Keystore (P-256 поддержан везде, в отличие от X25519),
десктоп — программный ключ. `shared = ECDH(priv, peer_pub)` →
`HKDF-SHA256(salt=transcript_hash, ikm=shared, info="deunlock-bond-v2")` →
`bond_key[32]`. Дополнительно `handshake_key` и `session_key` из того же HKDF
с разными `info`. После этого MAC челленджа становится настоящим, а UUID —
непредсказуемым.

## D-02 — телефон как signing oracle (medium)

Подписывается тело челленджа (`ApproveViewModel.kt:329`,
`signWire(bondKey, challengeFrame)`); тело содержит только version || nonce.
Привязки к идентичности десктопа нет. `docs/reference/protocol.md:61` прямо
говорит, что Android-колбэки снимают последние 16 байт и не вызывают
верификатор MAC. Итог: любое BLE-устройство рядом может заставить телефон
подписать произвольный nonce.

Само по себе это не даёт входа (ответ валиден только для челленджа настоящего
десктопа), но это оракул подписи и маскировка для relay-атак.

**Исправление.** После D-01: телефон проверяет MAC челленджа до биометрии и
показывает в UI подписанное имя десктопа. Подписываемый транскрипт:

```
"deunlock-v2" || host_id[32] || service || user || nonce[16] || ts_be[8]
```

## D-03 — отказ на телефоне съедает fallback (medium)

`crates/deunlock-pam/src/auth.rs:213` — таблица маппинга: `denied` и
`bad-signature` → `PAM_AUTH_ERR`; тесты это фиксируют (auth.rs:669-691).
Отказ пользователя на телефоне попадает в один из этих двух reason'ов.

При рекомендованной схеме `auth required pam_deunlock.so` + `pam_unix` после
него `PAM_AUTH_ERR` означает, что стек уже провален и пароль не спросят:
нажали «Отклонить» — остались без входа в этой попытке.

**Исправление.** Отдельный reason `user-declined` → `PAM_AUTHINFO_UNAVAIL`
(падаем на `pam_unix`, пароль спрашивается), с явной строкой в audit log.
Безопасность не страдает: fallback по-прежнему требует пароль.
`bad-signature` остаётся `PAM_AUTH_ERR` (это уже подозрительно).

## D-04 — PAM доверяет строке, а не структуре (medium)

`outcome_reason_to_pam` (`auth.rs:213-227`) превращает `reason == "ok"` в
`PAM_SUCCESS`, не проверяя наличие подписи и не сверяя nonce с тем, который
запрашивали (`protocol.md:76`). Сейчас это спасает только 0o600-сокет +
`SO_PEERCRED` (`crates/deunlock-presenced/src/server.rs:41,293`).

**Исправление.** Типизированный ответ RPC: `Verified { peer_id, nonce,
service, user }` | `Declined` | `Unavailable(reason)`. PAM проверяет, что
вернувшиеся `nonce/service/user` совпадают с запрошенными, иначе
`PAM_AUTH_ERR`. Тест на подмену nonce обязателен.

## D-05 — нет шифрования и forward secrecy (medium)

Челлендж и подпись идут открытым текстом. Для BLE это терпимо, для Wi-Fi
(наш основной транспорт) — нет: в LAN трафик виден, и подпись телефона
утекает наблюдателю.

**Исправление.** После D-01 — эфемерный ECDH на каждый unlock →
`XChaCha20-Poly1305` на все сообщения, ключ выводится из `bond_key` и
эфемерных ключей. Даёт forward secrecy: компрометация `bond_key` не расшифрует
прошлые сессии.

## D-06 — нет привязки к сервису (low)

`service` (`sudo`, `gdm`, `polkit`) не входит в подписываемый транскрипт:
подпись, выданная для одного сервиса, валидна для другого в пределах TTL.
Стоит 20–40 байт, чинится вместе с D-02.

## D-07 — пейринг без QR-связывания (low)

6-значный LESC numeric compare + 4 эмодзи — рабочая, но слабая защита от
MITM при пейринге. Для Wi-Fi-транспорта QR даёт структурную гарантию:
`deunlock://pair?v=2&host=<b64 host_id>&pk=<b64 ecdh_pub>&fp=<hex8 tls pin>&n=<b64 nonce>` —
одноразовый, подписанный, с пиннингом TLS-сертификата.

## Что в форке уже сделано

- Дерево переименовано (`syauth` → `deunlock`, включая имена крейтов, Kotlin-
  пакет, systemd-юниты, PAM-модуль, env-переменные).
- `cargo check --workspace --all-targets` — чисто, 44 с.
- MIT-атрибуция исходного проекта восстановлена (`LICENSE` + `NOTICE`).
- 63 файла с тестами, `unsafe_code = "deny"`, fuzz-таргет на парсер фреймов,
  `catch_unwind` на границе FFI — это сохраняем.

## Порядок работ

1. **P0** — D-01 + D-02 + D-06: протокол v2 (ECDH, транскрипт, проверка MAC
   на телефоне). Ломающее изменение wire format → новая версия фрейма `0x02`,
   старый `0x01` отвергается.
2. **P1** — D-04 + D-03: типизированный RPC, проверка nonce в PAM, отдельный
   `user-declined`.
3. **P2** — Wi-Fi транспорт: mDNS + TLS 1.3 с пиннингом + D-05 AEAD.
4. **P3** — D-07: QR-пейринг для Wi-Fi, LESC остаётся для BLE.
5. **P4** — UI: один экран на Android, четыре команды в CLI.

Каждый пункт закрывается тестом; без теста пункт не считается сделанным.

---

## Статус на 2026-11-10 (после P0 части 1 и 2)

| ID | Статус | Чем закрыто |
|----|--------|-------------|
| D-01 | ядро готово, проводка — P2 | `kex.rs`: ECDH P-256, `bond_key` из shared secret с привязкой к host_id/phone_id/nonce, key separation для MAC-ключа |
| D-02 | ядро готово, телефон — P2 | `transcript.rs`: подписываемый транскрипт с host_id/service/user/nonce/ts; `challenge.rs`: payload `DLC2` в фрейме v2 |
| D-03 | **закрыто** | все-нулевая подпись → `ChallengeOutcome::UserDeclined` → `user-declined` → `PAM_AUTHINFO_UNAVAIL` (падение на `pam_unix`) |
| D-04 | **закрыто** (nonce-часть); service/user требуют `pam_get_item` — отдельный шаг | PAM сверяет эхо `peer_id`+`nonce` и согласованность `ok`/`reason`/`signature`; демон использует nonce вызывающего, а не свой |
| D-05 | открыто | AEAD сессии — вместе с Wi-Fi транспортом (P2) |
| D-06 | **закрыто** | сервис и пользователь входят в MAC-транскрипт: тег от `sudo` не проходит для `gdm` |
| D-07 | открыто | QR-пейринг — P3 |

Тесты: `deunlock-core` 104, `deunlock-presenced` 5 в `challenge_flow` (включая
`zero_signature_is_classified_as_user_declined`), полный workspace — 501 passed,
0 failed. `cargo clippy -D warnings` по core/presenced/pam — чисто.

D-04 закрыт по nonce-половине: демон использует nonce вызывающего (раньше
игнорировал и генерировал свой), ответ эхом несёт `peer_id` + `nonce`, PAM
сверяет их байт-в-байт и отвергает несогласованные `ok`/`reason`/`signature`.
Остаток: `service`/`user` в запросе — нужен `pam_get_item`, это отдельный шаг
вместе с v2-проводкой.

## Постоянная идентичность десктопа (предусловие D-02)

До этого шага `deunlock pair` генерировал хост-ключ на каждый запуск и нигде
его не сохранял: телефон пиннил публичный ключ, которого после выхода процесса
не существовало. Добавлен `deunlock-core::host` — один Ed25519-ключ на машину
(`/etc/deunlock/host.key`, 0600 в 0700, атомарная запись), `host_id =
BLAKE3(public_key)[..32]`, загрузка отказывается принимать файл с правами
шире 0600 и не пересоздаёт битый файл (иначе все бонды тихо ломаются).
`deunlock pair --host-key` использует его вместо одноразового ключа.
Следующий шаг — загрузить эту же идентичность в демон и строить `ChallengeV2`
с `host_id` в транскрипте.

## Проводка v2 (daemon + PAM)

- `Request::Challenge` несёт `service`/`user`; PAM читает их через
  `pam_get_item(PAM_SERVICE)` / `pam_get_item(PAM_USER)` в `entry.rs`
  (единственный unsafe-блок, добавлен `unsafe extern "C"` без внешних крейтов).
  Если элемент недоступен — `unknown`, а не падение.
- Демон при старте грузит `/etc/deunlock/host.key` (переопределяется
  `DEUNLOCK_HOST_KEY`). Есть идентичность → `issue_challenge_v2`: транскрипт
  `host_id‖service‖user‖nonce‖ts`, `ChallengeV2` в фрейме `0x02`, подпись
  телефона проверяется над теми же байтами (`verify_transcript`).
  Нет идентичности (машина ещё не пейрилась) → прежний v1-путь, чтобы
  полуустановленная система не блокировала вход.
- Проверено тестами: кадр `0x02` декодируется, MAC сходится с bond_key,
  транскрипт содержит ожидаемые поля, подпись над транскриптом принимается;
  подпись, выданная для `gdm`, не принимается для `sudo`.

## Телефонная половина v2 (mobile crate + Kotlin)

- `deunlock-mobile`: `parse_challenge(bond_key, frame)` понимает обе версии
  провода, **проверяет MAC до всякой подписи** (закрывает D-02: без bond_key
  телефон больше не оракул подписи) и возвращает `ChallengeInfo`
  (`service`, `user`, `host_id`, `nonce`, `issued_at`, `sign_payload`).
- `build_response_signature(...)` подписывает `sign_payload` (для v2 —
  канонический транскрипт) и отдаёт сырые 64 байта, которые демон и разбирает
  через `parse_signature`. Раньше Kotlin отправлял целый v1-фрейм, который
  демон как подпись не принял бы — это была реальная несостыковка живого пути.
- Kotlin: `UniffiWireSigner` вызывает `buildResponseSignature`; экран
  подтверждения показывает `service · user` из транскрипта (для v1-кадров
  строка не рисуется), `WireSigner.describeChallenge` — шов, который в тестах
  возвращает пустую строку.
- Статус проверки: Rust-часть покрыта тестами (517 в workspace). Kotlin **не
  компилировался** — на машине не было Android SDK; SDK поставлен
  (`/mnt/king4tb/tools/android-sdk`, platform 35, build-tools 35.0.0), но для
  сборки APK нужны NDK, rustup-таргеты `*-linux-android`, `cargo-ndk` и
  `uniffi-bindgen`.

## Транспорт Wi-Fi (D-05): `deunlock-net`

- `identity.rs` — самоподписанный сертификат десктопа, `SHA-256(cert DER)` = пин
  (32 байта, рисуется в QR). Файлы `0600` в каталоге `0700`, атомарная запись,
  половинчатая идентичность **не пересоздаётся**: потеря ключа = повторный
  пейринг, а не тихая подмена.
- `tls.rs` — TLS 1.3, ALPN `deunlock/2`; серверная конфигурация из идентичности,
  клиентская — с `ServerCertVerifier`, который принимает ровно один пин
  (constant-time сравнение). Нужен и телефону как контракт, и тестам: неверный
  пин реально рвёт handshake, а не «считается» неправильным.
- `framing.rs` — `u32be(len) || body`, жёсткий потолок 4 КиБ: префикс «4 ГиБ»
  отвергается **до** выделения памяти.
- `mdns.rs` — `_deunlock._tcp.local.` с TXT `v=2`, `id=<host_id>`, `fp=<16 hex>`;
  префикс отпечатка нужен только чтобы понять, какой из спаренных десктопов
  отвечает, доверие всё равно решает полный пин.
- Тесты: 16 (фрейминг, границы, усечение, пин/неверный пин, ALPN, режимы
  файлов, отказ при 0644, mDNS-запись).

**Не сделано на этом шаге:** `LanPeripheral` (реализация трейта `Peripheral`
поверх TLS-сессии) и аутентифицированный hello телефона. Дизайн решён:
hello = MAC под `derive_auth_mac_key(bond_key)` над
`"deunlock-lan-hello-v1" ‖ host_id ‖ phone_id ‖ TLS-exporter`, то есть
привязка к конкретной сессии — перехваченный hello не переигрывается.

## Wi-Fi-сессии: hello, `Peripheral`-бэкенд, композит, проводка

- **hello (аутентификация телефона).** TLS доказывает, что десктоп — тот, кого
  пиннили; про телефон он не говорит ничего. Поэтому первое сообщение сессии —
  `"DLH1" ‖ host_id[32] ‖ peer_id[32] ‖ TLS-exporter[32] ‖ tag[32]`, где
  `tag = BLAKE3_keyed(derive_auth_mac_key(bond), "deunlock-lan-hello-v1" ‖ …)`.
  Экспортёр привязан к конкретной TLS-сессии, поэтому записанный hello
  бесполезен на другом соединении: реплей умирает на теге. Неизвестный
  `peer_id` → `PinMismatch`, чужой `host_id` → отказ, чужой экспортёр → отказ.
- **`LanPeripheral`** реализует тот же трейт `Peripheral`, что и BLE: протокол
  не знает, по какому транспорту идёт челлендж. `notify_challenge` без живой
  сессии возвращает `Backend`, `wait_for_response` — `ResponseTimeout` по
  дедлайну PAM.
- **`CompositePeripheral`** (в `deunlock-presenced`): челлендж уходит во все
  бэкенды, ответ берётся первый пришедший; ошибка возвращается, только если
  отказали все, причём таймаут предпочитается «нет сессии» — в логе будет
  «телефон не ответил», а не «телефона тут нет».
- **Проводка в демон:** opt-in `DEUNLOCK_LAN=1` (`DEUNLOCK_LAN_PORT`, по
  умолчанию 47823; `DEUNLOCK_NET_CERT`/`DEUNLOCK_NET_KEY`, по умолчанию
  `/etc/deunlock/net.{crt,key}`). Недоступный слушатель — warn и работа на BLE,
  а не отказ старта. mDNS-запись живёт ровно столько же, сколько слушатель.
- **Проверено живьём** (демон с `--peripheral=fake`, временные пути):
  `LISTEN 0.0.0.0:47899`, в логе `advertising deunlock on the LAN`,
  `LAN transport ready … ip=192.168.10.249 port=47899`,
  `transports wired backends=["ble","lan"]`, `net.crt`/`net.key` — `-rw-------`,
  после остановки порт закрыт.
- Тесты: `deunlock-net` 25 (фрейминг, пин/неверный пин, hello: позитив, чужой
  хост, реплей на другую сессию, чужой bond, мусор; полная сессия челлендж→
  подпись; таймаут молчащего телефона; челлендж без сессии), `composite` 4
  (первый ответ побеждает, «никто не может» — ошибка, таймаут в приоритете,
  повторная регистрация пира не ломает). Workspace: **546 passed, 0 failed**.

**Остаётся:** телефонная половина LAN (Kotlin: pinned `SSLSocket` + hello) и
первый живой прогон на устройстве — без APK на телефоне это не проверяемо.

## Телефонная половина Wi-Fi (Kotlin)

- `lan/LanEndpoint.kt` — адрес, порт и **пин** (`SHA-256(cert DER)`, 32 байта);
  пин обязателен, короткий или не-хексовый отвергается до подключения. `ALPN =
  deunlock/2`, потолок кадра 4 КиБ — те же константы, что на десктопе.
- `lan/PinnedTrustManager.kt` — принимает ровно один сертификат. Цепочка и имя
  хоста **сознательно** не проверяются: сертификат самоподписанный, и пин —
  более сильное утверждение, чем любая цепочка. В комментарии это записано,
  чтобы поздний читатель не «починил» код, вернув CA.
- `lan/LanFrames.kt` — `u32be(len) ‖ body`. Здесь тест поймал настоящий баг:
  длина читалась как `Int`, и префикс `0xFFFFFFFF` превращался в `-1`,
  проходя проверку `<= MAX` (дальше — `NegativeArraySizeException`). Теперь
  длина считается в `Long` и проверяется на диапазон `0..MAX`.
- `lan/LanClient.kt` — TLS 1.3 + ALPN, затем порядок «десктоп говорит первым»:
  `DLS1`+nonce → hello → кадр челленджа → подпись 64 байта. Транспорт вынесен
  за интерфейс `LanTransport`, поэтому вся логика отказа проверяется в JVM без
  телефона; ни один шаг не доходит до подписи, пока не пройден предыдущий.
- `lan/LanWiring.kt` — мост в Rust-ядро: hello через `buildLanHello`, подпись
  через `buildResponseSignature` (то есть MAC проверяется до биометрии).

**Проверено:** `./gradlew testDebugUnitTest` — 130 тестов, 0 падений;
`assembleDebug` — BUILD SUCCESSFUL. Живой Wi-Fi-сессии на устройстве ещё не
было.

## QR-пейринг (D-07) — десктопная половина

- `deunlock-core::qr_pair` — формат кода:
  `"DLQR1" ‖ base64url(version ‖ host_id ‖ host_pubkey ‖ host_len+host ‖
  port ‖ tls_fingerprint ‖ pairing_secret ‖ expires_at)`. Внутри — всё, что
  нужно телефону: **кто** этот десктоп (host_id + публичный ключ), **куда**
  идти (LAN-адрес и порт), **что** пиннить (SHA-256 сертификата) и 256-битный
  секрет пейринга, увиденный глазами, а не присланный по сети.
- Разбор строго ограничен: префикс, версия (неизвестная — отказ, а не догадка),
  длина хоста 1..=63 и только `[A-Za-z0-9._:-]`, проверка на обрезание по каждому
  байту, отказ на хвостовые байты, срок годности. Все чтения — через
  bounds-checked курсор, паник на мусоре нет.
- `deunlock pair-qr --lan-host … [--port] [--ttl] [--png] [--quiet]` —
  печатает payload, пин и срок; PNG через `qrencode`, если он есть (иначе
  внятная ошибка, а не тихий пропуск). Секрет берётся из `OsRng`; предсказуемый
  секрет = подделанный бонд, поэтому падение RNG — ошибка.
- **Проверено живьём:** `payload: DLQR1…`, 211 символов, префикс на месте,
  padding отсутствует, пин и срок печатаются, `--quiet` отдаёт только payload.
- Тесты: 8 в core (round-trip, url-safe алфавит, просрочка, чужой префикс,
  новая версия, обрезание по каждому префиксу, кривой host, секрет не виден
  как hex) + 4 в CLI (offer несёт реальные host_id/ключ/пин, два кода никогда
  не делят секрет, payload сканируется обратно в тот же offer, отсутствие host
  identity — ошибка, а не пустой код). Workspace: **567 passed, 0 failed**.

**Не сделано:** телефонная половина — сканер QR, сохранение пина и вывод бонда
из секрета; до неё рабочий путь пейринга остаётся BLE. D-07 закрыт лишь
наполовину — это записано честно.

## QR-пейринг: бонд из секрета

- Секрет из QR — 256 бит, увидённых глазами. Он и есть основа бонда, ECDH не
  нужен: сеть не может повлиять на результат.
- `bond = BLAKE3-derive_key("deunlock-bond-qr-v1")(secret ‖ host_id ‖ phone_pubkey)`.
  Чего в нём **нет**: TLS-отпечатка десктопа (его уже доказало соединение) и
  адреса телефона.
- `phone_pubkey` — существующий Ed25519-ключ телефона (тот, из которого считается
  `peer_id`). Отдельная P-256 пара не заводится: меньше ключей — меньше мест, где
  можно ошибиться.
- Обмен: телефон `"DLP1" ‖ phone_pubkey[32] ‖ tag[32]`, десктоп отвечает
  `"DLP2" ‖ tag[32]`. Оба тега проверяются в постоянное время, домены разные
  (`…-pair-request-v1` / `…-pair-accept-v1`), поэтому теги не взаимозаменяемы —
  это отдельный тест.
- Ответ десктопа существует ровно для одного: чтобы телефон узнал, что машина на
  другом конце **тоже** держала секрет. Без него телефон, отсканировавший код,
  мог бы связаться с машиной, которая просто переслала байты.
- Экспорт в телефон: `deriveQrBond`, `buildPairRequest`, `verifyPairAccept`
  (последняя возвращает `false` при несовпадении тега — «эта машина не держала мой
  код» это ответ, а не сбой; кривая запись — ошибка).
- **Проверено:** 8 тестов в core (round-trip, одинаковый бонд с обеих сторон,
  зависимость от секрета/хоста/ключа, отказ на чужой секрет и чужой host, теги не
  взаимозаменяемы, обрезание по каждому префиксу, нулевой ключ) + 4 в mobile
  (телефон и десктоп сходятся на бонде, подделанный accept → `false`, кривой
  accept → ошибка, короткие входы отвергнуты). Workspace: **579 passed**, clippy
  чист, AAR пересобран, Android `testDebugUnitTest` — BUILD SUCCESSFUL.

**Не сделано:** десктопная сторона приёма `DLP1` — файл оффера в `/run/deunlock/`,
обработка записи в LAN-слушателе, запись бонда в `BondStore` и перезагрузка набора
пиров. До этого пейринг по-прежнему только через BLE.

## QR-пейринг: сквозной путь на десктопе

- `deunlock pair-qr` кладёт оффер в `/run/deunlock/pairing.offer` (0600, атомарная
  запись), путь переопределяется `--offer-path` / `DEUNLOCK_PAIRING_OFFER`. Без
  файла слушатель отвергает любой `DLP1` — «нет оффера, нет пейринга».
- Оффер **одноразовый**: `FilePairingOffers::take` читает и удаляет файл. Плохой
  или просроченный файл тоже удаляется, чтобы не блокировать следующую попытку.
  Сканированный код покупает ровно одну попытку; это дешевле, чем 256-битный
  секрет, лежащий в `/run` весь TTL.
- `LanServer::with_pairing(offers, sink)` — без этого `DLP1` отвергается: телефон
  без бонда не должен заставлять слушатель работать. Демон армирует пейринг
  всегда (при отсутствии файла это ничего не стоит) и логирует
  `QR pairing armed on the LAN listener`.
- `QrBondSink` пишет `bonds.toml` через `BondStore` — файл уже под inotify, поэтому
  оркестратор сам перезагружает набор пиров; дублировать логику reload не нужно.
  Ключ пишется `persist_pair_bond_key` (0600). Отозванный телефон перепейриться не
  может: `revoked` — это явный отказ, а не приглашение.
- `deunlock pair-probe --payload DLQR1…` — временная замена телефона: пиннинг
  сертификата, `DLS1`, `DLP1`, проверка `DLP2`. Пока устройства нет, это
  единственная честная проверка всего пути.
- **Проверено живьём** (реальный демон, реальный `bonds.toml`, без заглушек):
  `QR pairing armed`, оффер 191 байт `-rw-------`, `step 1/2/3` пройдены,
  `pairing: ok`, бонд записан (`peer_id`, pubkey телефона, `name`, `status`),
  `keys/<peer_id>.bin` создан, оффер израсходован, повторная попытка отвергнута
  (`no pairing offer is pending`). Тесты: 4 новых в `lan_peripheral` (успешный
  пейринг, нет оффера, чужой секрет, слушатель без пейринга) + 1 файловый
  (одноразовость), workspace **588 passed**, clippy `-D warnings` чист.

**Осталось в D-07:** телефонная половина — сканер QR и сохранение пина; на
устройстве ничего из этого ещё не запускалось.

## Живой прогон с настоящим телефоном (Redmi 2322PCD1G, HyperOS 3.0 / Android 16)

Telephone pair against the daemon, no test doubles. Two real defects fell out
of the run, both invisible to the test suite because the fakes never model
BlueZ wire limits or advertisement-slot lifetime.

### D-08 (high) — the pair watcher accepts any phone, and the LESC digits go nowhere

`deunlock-presenced` registers the pair service unconditionally and, on an
incoming public key, derives a bond and persists it. There is no out-of-band
confirmation and no operator presence check: the four-emoji/one-time-code step
that `deunlock pair` (CLI) enforces does not exist in the daemon path.

The LESC numeric comparison is also a formality. The BlueZ agent used to be:

```rust
request_confirmation: Some(Box::new(|_req| Box::pin(async move { Ok(()) })))
```

`RequestConfirmation.passkey` was discarded, so the phone asked the operator
"Do these match?" while the desktop displayed nothing to compare against. The
handler now logs the passkey at `warn` — a headless daemon has no other channel
— so the comparison is at least *possible*. Making it *mandatory* (refusing a
bond whose digits nobody confirmed) is still open: it needs a decision about
whether the daemon may block on operator presence, and where that answer is
entered.

Mitigation in this commit: once any bond exists the pair-mode UUID is no longer
advertised (see D-09), so a bonded desktop stops inviting new phones. A phone
that connects to the pair service anyway is still accepted without OOB.

### D-09 (high) — a second 128-bit UUID made every rotation after pairing fail

`build_uuid_union` always added the pair-mode UUID on top of the session UUIDs.
A legacy advertisement holds 31 bytes: Flags take 3, one 128-bit UUID takes 16.
Pair UUID + session UUID is 35 bytes, so BlueZ rejected the registration with
`Failed to register advertisement` — starting exactly one second after the first
bond was written, i.e. right after the very first successful pairing:

```
pair: bond persisted; orchestrator reload requested peer_id=d522633e...
reload trigger=pair peers_before=0 peers_after=1
WARN rotation failed error=advertise: Failed to register advertisement
ERROR daemon exited with error=Bluetooth transport unavailable
```

Pair mode is now a *mode*: no bonds → pair UUID only; bonded → session UUIDs
only. This also tightens D-08: pair mode stops being discoverable once the
desktop has a phone.

### D-10 (medium) — one lost advertisement race killed the daemon

Registration is asynchronous on the BlueZ side, so a rotation that drops the old
advertisement and immediately registers the new one can lose the race. The code
retried zero times and treated the error as fatal: `transport_ready` went false
on the first failure, the run loop drained, and the process exited — two seconds
after a successful bond. Rotations now retry five times with a 60 ms backoff,
and readiness only drops after three consecutive failed ticks.

## Первая живая разблокировка: `pamtester: successfully authenticated`

End-to-end on the real phone, through a real PAM stack
(`/etc/pam.d/deunlock-test` → `pam_deunlock.so` → daemon → BLE → fingerprint):

```
pamtester: successfully authenticated
tx peer=a4343c2dd72d042277a4120d64fdd24a outcome=ok  (4.1 s)
```

Getting there exposed four defects, each of which produced the same useless
symptom — `bad-signature` or `response-timeout` — while the operator was doing
exactly the right thing.

### D-11 (high) — the phone signed the frame body; v2 verifies a transcript

The approval path (`ChallengeApprovalActivity` → `AndroidBiometricGate`) stripped
a 16-byte tag and signed `version ‖ nonce ‖ payload`:

```kotlin
val challengeBody = frameBytes.copyOfRange(0, frameBytes.size - 16)
```

That is the v1 contract (`verify_frame`). Since v2 the desktop verifies
`AuthTranscript` (D-04), so the signature was valid and over the wrong bytes —
indistinguishable, from the daemon's side, from a wrong key. Two earlier rounds
were wasted on the key hypothesis before the operands were dumped and checked
offline.

The signing bytes now come from the same Rust parser the desktop's transcript
comes from: `parseChallenge(bondKey, frameBytes).signPayload` — MAC-checked
first, so "sign before authenticating the frame" is no longer expressible. A
`SigningPayloadProvider` seam keeps JVM tests off the native library.

### D-12 (high) — the daemon's deadline was capped in the PAM module

```rust
stream.set_read_timeout(Some(auth_timeout.min(DAEMON_RESPONSE_BUDGET)))  // 8_000
```

`DAEMON_RESPONSE_BUDGET` silently truncated the raised `auth_timeout`: the daemon
waited 25 s while PAM gave up at 8. The budget is now 30 s and documented as
"must exceed the daemon's deadline" — the daemon's typed `response-timeout`
answer is worth waiting for.

### D-13 (medium) — eight seconds is not enough for a fingerprint

Measured on the device: challenge written, phone's response characteristic
written **9.1 s later** — notification, screen wake, biometric prompt, signature.
The old 8 s expired 1.1 s before a legitimate approval; a second attempt showed
the same. `DEFAULT_AUTH_TIMEOUT` is now 25 s (daemon) / 27 s (PAM), and PAM
accepts `timeout=<ms>` so an operator can tune a slow device without rebuilding
the module. SPEC §4.3's "≤1.2 s offline detect" is unaffected and structural: an
unreachable peer has no characteristic to write to, so the call fails in 0 ms
(observed live: `outcome=transport-error` with `t_start_ms == t_end_ms`).

### D-14 (high) — `revoke` is one-sided

`revoke` in the app deletes the phone's bond record only. The desktop keeps
its row in `/var/lib/deunlock/bonds.toml`, so it continues to challenge a device
that no longer holds the key — and, because D-09 makes pair mode exclusive to
"no bonds", it also stops advertising itself as pairable. The user-visible
result was "the computer is not in the list" with a perfectly healthy daemon.

Open. Candidate fixes: have the phone send a revoke frame over the authenticated
channel; let the desktop drop a bond after N consecutive transport failures; or
make desktop-side `deunlock revoke` the documented step and surface it in the
app. Whichever wins, the two stores must not be able to disagree silently.

### D-14 — протокол отзыва (desktop half, done)

The phone cannot open a socket to the daemon; its only channel is the GATT
response characteristic. So revocation travels there, and it is authenticated:

```text
"DLR1" ‖ timestamp_ms: u64 BE ‖ tag: [u8; 32]
tag = BLAKE3_keyed(derive_auth_mac_key(bond), "deunlock-revoke-v1" ‖ timestamp_be)
```

The tag proves possession of the bond key the desktop already holds, so a
stranger cannot retire somebody else's bond — the test
`a_revocation_under_the_wrong_key_changes_nothing` pins exactly that: a forged
frame leaves `bonds.toml`, the key file and the live peer untouched and is
reported as `bad-signature`. A forged frame is therefore not a remote revoke
gadget.

On receipt the daemon does three things together, because doing fewer is how the
two sides disagreed in the first place: removes the record from `bonds.toml`,
deletes `keys/<peer_id>.bin`, and reloads the peer set so the GATT registration
and the advertised UUIDs drop with it. The outcome is its own reason
(`bond-revoked`), mapped by PAM to `PAM_AUTHINFO_UNAVAIL` so the password path
still works and the operator is told to re-pair — instead of `bad-signature`,
which says "your fingerprint did not match" when in truth the bond is gone.

Timestamp window is ±10 minutes: revocation is idempotent, so the worst a
captured frame can do is delay a re-pair, and only while it is fresh.

**Still open — the phone half.** Delivering the frame needs the app to keep a
tombstone for a revoked bond: today `onBondRevokeTapped` deletes the record and
the Keystore entry, after which the service has no peer to attach a GATT client
to and cannot answer the next challenge at all. Two shapes are possible and this
needs a decision rather than a guess:

1. *Tombstone until delivered* — keep the record, mark it `revoke-pending`, show
   the home card as unpaired, and answer the next challenge with `DLR1` instead
   of biometrics. Costs: a bond that outlives the operator's intent if the
   desktop is never in range again.
2. *Best effort now, expire later* — send `DLR1` immediately if the peer is
   connected, delete the record regardless, and let the desktop bound the damage
   with a staleness rule (drop a bond nobody has connected to for N days).

Until one is chosen, the operator-facing path is `deunlock revoke <peer>` on the
desktop: it marks the bond `Revoked`, the reload drops the peer, and pair mode
returns — verified by `compute_new_set` filtering `is_revoked()`.

### D-14 — phone half: the tombstone

The desktop side landed first (the `DLR1` frame, verified under the bond key,
dropping record + key file + live peer). The phone half needed a decision, and
the decision was: **destroy what grants access, keep what delivers the message**.

`onBondRevokeTapped` now deletes the Keystore entry *first* and only then writes
the tombstone. If the delete fails, the record is left exactly as it was — a
tombstone holding a live alias would be worse than no revoke at all, because it
looks finished while the phone can still approve.

What survives is the record's symmetric MAC key, which cannot sign an approval.
What does not survive is the Ed25519 private key, so after the tap there is no
cryptographic way for this phone to authorize anything for that desktop. The
home screen shows an unpaired device — the operator sees the effect immediately,
not seven days later.

Delivery rides the next challenge: when the GATT client reports one, the service
notices `revokePending` and answers with the revoke frame instead of opening the
biometric prompt. A successful write clears the tombstone; a failed one keeps it
and retries on the next contact. The desktop, in turn, verifies the frame,
deletes its half and reports `bond-revoked`.

Bounds, because "keep it just in case" is how secrets outlive intent:

* the tombstone carries `revoke_deadline_ms = now + 7 days`; past that it is
  dropped and the phone stops holding a key for a bond the operator retired.
* the on-disk schema did not move. The keys are optional on read, so an older
  build ignores them and a newer one reads their absence as "not revoked".
* the parser gained a long map: a millisecond deadline does not fit in an Int,
  and widening the parser was cheaper — and stricter — than quoting numbers.

Residual, and now covered by the staleness rule: a tombstone that expires
undelivered leaves a bond on the desktop that nothing will ever answer.

### The staleness rule (desktop, independent of revocation)

A bond outlives the phone in more ways than revocation: lost, wiped, factory
reset. `pam_deunlock.so` installs as `sufficient`, so a dead bond costs the full
human-scale deadline (25 s) **before** the password prompt, on every
authentication, indefinitely. Measured on the real phone: an approved round-trip
is ~4 s.

`PresenceStore` persists one line per peer — when it last *answered* (a
signature, a denial, or a revocation; a challenge that gets no reply is not an
answer) — beside the bond store, so a daemon restart does not make a dead bond
look fresh. A peer that has not answered for a day gets a 3 s deadline instead of
whatever the caller asked for. Never-seen peers keep the requested deadline:
never-seen is indistinguishable from "paired, and the daemon just restarted",
and shortening it would break the first legitimate unlock after a reboot.

The rule never deletes a bond. Discarding key material is a security decision,
and the daemon is not the right place to make one unattended; it only stops
paying for a peer that is not there. `deunlock status` prints `last_seen` and a
`live`/`stale` column so the operator can see why a machine behaves this way.

### D-15 (high) — two challenge factories, and the revocation was in one

The phone half of D-14 shipped and did nothing on the real device. `revoke` wrote
the tombstone, the home screen went unpaired, the desktop challenged — and the
phone opened the biometric prompt anyway, then let the deadline expire. Nobody
was wrong about the protocol: the tombstone was on disk and correct, and the
daemon never received a single byte.

Cause: the app installs `gattClientFactory` **twice**. The service installs a
default on start; `MainActivity.installPersistentClientFactory` replaces it on
launch. The revocation branch was added to the service's copy, so the factory
that actually ran — the activity's — went straight to `signingPayloadFor` and
`launchApprovalActivity`. Two wirings of the same callback is the defect; the
missing branch was only its symptom.

Both factories now call one entry point, `DeUnlockCompanionService.handleChallenge`,
which decides between the revocation frame and the approval prompt and cannot be
half-updated: a change to the decision lands in both call sites because there is
only one decision.

Verified on the device after the fix:

```
11:31:52.948 I/deunlock.bg: revoke: delivered to the desktop peer=04:EA:56:C2:0E:51; tombstone cleared
11:31:53.786 WARN phone revoked its bond; dropping the desktop half
11:31:53.790 INFO bond record removed
11:31:53.790 INFO bond key file removed
11:31:53.791 INFO reload trigger=revoked peers_before=1 peers_after=0
11:31:53.801 INFO tx outcome=bond-revoked
```

`bonds.toml` drops to zero bonds, `keys/` is empty, and `pamtester` fails with
`PAM_AUTHINFO_UNAVAIL` — the password path, as designed, not a silent hang.

The rotation tick also logs the pair-mode transition now
(`advertising in pair mode: no bonds, pair service discoverable`). It is the
question an operator asks immediately after a revoke — "can the phone find this
computer again?" — and at zero peers the tick had nothing else to say.

### D-16 (low, but it cost hours) — `advertising` was a constant

`deunlock status` printed `advertising: false`, always: `ADVERTISING_STATE_V01`, a
v0.1 placeholder, hard-coded and never wired. On a machine whose daemon was
advertising perfectly well, the operator's most authoritative-looking line said
it was not — which is exactly the kind of confident lie that sends someone
chasing the wrong defect (in this session, "the computer is not in the list").

The daemon has reported `transport_ready` for a while; the CLI simply never
asked. It does now, and `advertising` is `Option<bool>`: `true`, `false`, or
`unknown` when the daemon is down or predates the field. A diagnostic surface
must be allowed to say "I do not know" — that is a different, and much more
useful, answer than a constant.

### D-08 (high) — the first bond needed nothing but a nearby phone, CLOSED

Two halves of one defect.

**The bond key was public.** `bond = HKDF(host_pubkey ‖ phone_pubkey)` — no salt,
no secret. `phone_pubkey` is public by construction (it is peer_id's preimage and
travels in every Hello), and `host_pubkey` is written onto the pair
characteristic the phone reads. Anyone who knew both could compute the bond of a
phone they had never touched.

**Nobody was in the loop.** The pair service is registered whenever a desktop has
zero bonds, which is exactly the state a fresh install sits in. It accepted
whichever phone wrote first, at any hour, with no operator action and no expiry.

Fix, and why this shape:

- `deunlock pair-code` mints a single-use ten-character code (Crockford base32,
  no `I`/`L`/`O`/`U`), arms an offer file with a 5-minute expiry, and prints it.
- The phone reads the host pubkey off the pair characteristic, generates its own
  random 256-bit bond, and writes `DLPB1 ‖ phone_pubkey ‖ tag ‖ bond`, where
  `tag = KDF(code, host_pubkey ‖ phone_pubkey ‖ bond)`.
- The desktop verifies the tag against the armed offer, spends the offer, and
  stores the phone's bond.

The code authenticates the handshake; it is **not** the key. Fifty bits is a
reasonable one-shot gesture and a terrible long-lived secret, so the bond stays
random and is never derived from the code. The bond is in the tag input, so a
relayed write cannot carry a substitute bond.

Refusals are distinct so the phone-side failure is diagnosable: no offer, expired
offer, QR-only offer, wrong code (counted, five attempts kill the offer), bond
swapped after signing, and the legacy 32-byte pubkey-only write (`NoCodeProof`) —
the shape that made the hole.

Phone half: a code field on the pairing screen, the code handed to the backend,
the frame built by the same Rust code the desktop verifies (`build_pair_write`
over UniFFI), and a plain refusal before any radio traffic when the code is empty.

Tests: `deunlock-core` code/tag/frame vectors; six verifier tests in
`runtime.rs` (accept-and-spend, wrong code counted, no offer, QR offer, five
strikes, swapped bond); Kotlin handover tests. Workspace 632 passed, clippy clean.

Still open on this front: a phone that has never been told the code can connect and
*write* — it just cannot produce a valid tag, so the desktop refuses it. That is
the intended shape, but it means the pair characteristic is a free attack surface
for garbage writes; a rate limit per BLE address is not implemented.

### D-18 (high) — the pair service vanished after the first pairing, CLOSED

`build_and_register_peer` registered a GATT application containing **only** the
session service of the peer being added; bluer's `Application` is a snapshot, so
every `add_peer` replaced the running registration. `remove_peer` dropped the
registration outright.

Consequences: the pair service existed only until the first phone paired, and a
desktop that had just been revoked advertised a pair-mode UUID with no service
behind it — the phone reported `pair service not present on bonded device`. A
second phone was impossible for the same reason.

Fix: one application holds the pair service plus one session service per bonded
peer, rebuilt from the stored bond keys whenever the peer set changes
(`rebuild_services`). Side effect: a second phone no longer evicts the first.

### D-19 (medium) — a second pairing attempt in one app session did nothing, CLOSED

`exchangeStarted` was a one-shot for the lifetime of the backend and
`lescResultDeferred` was created once. After a failed attempt the guard rejected
every later exchange silently, and `awaitLescResult` would have returned the first
attempt's result forever. The user retyped a code and nothing happened, with no
log line to explain it.

Fix: `beginAttempt()` re-arms the guard and installs a fresh deferred at the start
of every `pickPeer`; a Kotlin test asserts two attempts both reach the wire.

### D-20 (medium) — pairing left the phone unable to answer, CLOSED

The companion service starts on boot, on a 15-minute watchdog tick, or on CDM
proximity — never on pairing. The first unlock after pairing therefore failed with
`notification unavailable ... not connected`, while the phone looked correctly
paired. Fix: the persister starts the service as soon as the bond is on disk.

### D-21 (medium) — a refused proof was undiagnosable, CLOSED

The tag covers code, host pubkey, phone pubkey and bond; any stale input produces
the same `wrong pairing code`. Both sides now log 32-bit SHA-256 fingerprints of
each input, so a refusal is diagnosed by diffing two log lines instead of guessing.
Measured on the first live pairing: matching fingerprints, `code_len=10`.

### D-22 (medium) — the phone talked to dead GATT handles, CLOSED

The desktop mints new attribute handles every time it re-registers its
application; Android caches the service table per bonded device. The pairing
exchange discovered services without `refresh()`, so a write could report success
and arrive nowhere (measured: phone logged `post-bond exchange complete`, desktop
logged nothing). Fix: reflective `BluetoothGatt.refresh()` before discovery.

Second half: a persistent client that discovered services a moment before the
desktop registered the peer's session service logged `challenge characteristic not
present` and stopped retrying, leaving the phone connected and useless. It now
re-discovers after two seconds.

Verified live: `deunlock pair-code` → phone types the code → `pair: code proved` →
`phone subscribed via standard notifications` → `pamtester` → `successfully
authenticated`, desktop `outcome=ok`.

Still open: a desktop that already has one bond does not advertise the pair UUID
(31-byte legacy advertisement budget), so a second phone cannot be added without
revoking the first.

### D-23 (high) — the PAM module looked for a socket root does not own, CLOSED

`Config::resolve_socket_path` resolved `${XDG_RUNTIME_DIR}` or `/run/user/<euid>`.
PAM inside `sudo` runs as root, so euid is 0 and both paths point at a directory
with no daemon: the phone was never asked and every privileged prompt fell
straight through to the password, looking like "it does nothing".

Fix: `Config::for_pam_invocation` resolves the socket from the **PAM account's**
uid via passwd lookup, keeps an explicit `socket=` override, and falls back to
the environment only when the account is unknown.

Same defect in the audit line: PAM appended to `DEFAULT_BOND_DIR`
(`/var/lib/deunlock`, root-owned). It now uses the account's own
`~/.local/share/deunlock` when that exists.

### D-23b (high) — `install-pam` wired a timeout below the daemon's deadline

`DEFAULT_MODULE_ARGS` was `timeout=8000` while the daemon waits 25 s for a
fingerprint: PAM asked the phone, gave up after 8 s and prompted for the
password anyway. Now `timeout=27000`, with a test asserting the constant stays
above the daemon's budget.

### D-24 (medium) — a per-user install had no identity and could not pair

The daemon only *loaded* `/etc/deunlock/host.key`, so a user-service install
issued v1 challenges and `deunlock pair-code` refused to mint a code at all.
Both now use `load_or_create`: the first start mints the identity, `pair-code`
does too.

### D-25 (medium) — the pairing offer lived in a root-only directory

`DEFAULT_PAIRING_OFFER_PATH` was `/run/deunlock/pairing.offer`, which a
user-service daemon cannot write or read. It now resolves to
`$XDG_RUNTIME_DIR/deunlock/pairing.offer`, with the old path kept as the
fallback when the runtime directory is unset.

### Product install

`scripts/install-user-service.sh` (no sudo) builds release binaries into
`~/.local/libexec/deunlock`, creates `~/.local/share/deunlock` at 0700, writes
`~/.config/systemd/user/deunlock-presenced.service` with `Restart=on-failure`
and per-user paths, and restarts the unit. `scripts/install-pam-system.sh`
(sudo) installs `pam_deunlock.so` and inserts the `sufficient` line into a PAM
service, backing the file up first.

### D-26 (medium) — a phone cannot tell that the desktop forgot it, CLOSED

Observed live: the desktop's state was reinstalled under a new identity, so its
`bonds.toml` was empty while the phone still held a bond record from the previous
install. The phone then did the only thing it knows — connect, discover, fail to
find its session characteristic, reconnect:

```
deunlock.bg.persistent: services discovered status=0 n=4
deunlock.bg.persistent: challenge characteristic not present; retrying discovery
deunlock.bg.persistent: watchdog: setup incomplete after 15000ms — forcing reconnect
```

The pairing screen never appeared, so a fresh `pair-code` could not be used at
all. Locally removing the bond record was not enough either: the *running*
service re-persisted the in-memory bond after the file was deleted, so the app
kept believing it was paired until the process was force-stopped first.

Fix: `PersistentGattClient` counts consecutive discoveries that do not carry the
peer's session service. Three of them — enough to cover the desktop registering
the service a second after the phone connects — mark the bond
`DesktopForgotMarker` (a file in `files/`, so it survives process death), stop
the client, and the home screen says it outright:

```
session service absent after 3 discoveries; treating the bond as forgotten by the desktop
deunlock.bond.forgot: desktop no longer recognises this bond; pairing required
```

```
This phone is still bonded to deunlock,
but that computer no longer recognises it.
Pair again with a fresh code from `deunlock pair-code`.
```

The bond record and its Keystore key are untouched: only the claim "this phone
can unlock that computer" is withdrawn, and a completed pairing clears the marker
(`onPairingCompleted`, and a successful subscribe in the client). Verified live on
2026-11-12 by revoking on the desktop while the phone kept its bond.

**The first version of this fix introduced D-26b.** The client called `stop()` on
reaching the conclusion, and `stop()` is permanent: nothing restarts it. Pairing
again cleared the marker and logged `service already running; skip`, the phone
looked fine, and the daemon answered every prompt with `notification unavailable
... not connected`, so `pamtester` failed in 32 ms on the password fallback. The
client now *parks* instead — no radio work, one marker re-check every 30 s — and
resumes by itself when a new pairing clears the marker. Verified: `pamtester
sudo roma authenticate` → `successfully authenticated` in 3.9 s.

### Product loop verified end to end (2026-11-12)

systemd user service (`deunlock-presenced.service`, `Restart=on-failure`) →
`deunlock pair-code` → phone types the code → `pair: code proved` → phone
subscribes → `pamtester sudo roma authenticate` → `successfully authenticated`
(3.2 s, audit `success`) → plain `sudo true` → exit 0 in 12.2 s with a
fingerprint on the phone and no password typed.

### D-27 (medium) — a cancelled challenge kept the peer's only slot, CLOSED

W-1 cancels a challenge by closing the PAM-side socket as soon as the operator
types a password. The daemon did not notice: `handle_connection` awaited
`dispatch` for the full deadline and only then tried to write a reply nobody
was waiting for. The consequence was not invisible — every peer has **one**
challenge slot with a one-second queue (`BUSY_QUEUE_DEADLINE`), so the *next*
`sudo` inside twenty-five seconds came back `busy` instead of asking the phone.
An operator who typed a password once got a password prompt for the next
attempt as well, with nothing on screen to explain why.

Fix: for `Request::Challenge` the connection handler now waits for the caller's
hang-up *beside* the challenge (`tokio::select!`). EOF abandons the challenge,
which drops `issue_challenge`, releases the semaphore permit and leaves no
half-written reply. Other request kinds are unchanged.

Measured, both directions, in `crates/deunlock-presenced/tests/challenge_cancel.rs`:

```
# with the fix
test an_abandoned_challenge_frees_the_peer_slot ... ok        (0.25 s)
# with the select! removed (old behaviour), same test:
test an_abandoned_challenge_frees_the_peer_slot ... FAILED    (5.17 s)
```

Still open, and deliberately: the phone is **not** told. A challenge cancelled
from the terminal keeps its prompt on the phone until the phone's own deadline
runs out. Withdrawing it needs a desktop→phone cancel frame and a phone-side
handler, which belongs with the phone work in W-3; the desktop half is now
correct on its own (slot free, no phantom `busy`).

### W-1 — the terminal offers a choice instead of a wait (delivered 2026-11-12)

The module no longer asks the phone silently. On a terminal it prints one line,
reads it with echo off on the caller's own tty, and runs the challenge beside it:

```
Confirm on your phone, or type your password:
```

Shape of the race (`crates/deunlock-pam/src/choice.rs`):

- one `poll()` over two descriptors — the terminal and the daemon socket — so a
  keystroke and a signature are the same kind of event and neither can starve
  the other;
- **password wins**: the line is read in canonical mode (the kernel does the
  editing), the socket is closed (*that* is the cancellation, see D-27), and the
  bytes go to `pam_set_item(PAM_AUTHTOK)`; the module returns `PAM_IGNORE` so
  `pam_unix` verifies them. The module never decides that a password is correct;
- **phone wins**: the verdict is mapped exactly as before, and whatever was
  half-typed is thrown away with `tcflush(TCIFLUSH)` — a phone approval must not
  leave the first characters of a password in the queue for the next prompt;
- **neither**: the window expires, echo is restored, our line is closed with a
  newline, and the next module's password prompt appears on a clean line;
- echo is restored by `Drop` on the terminal guard, so every early return, error
  and panic leaves the operator's terminal as it was found;
- with no terminal (`cron`, a pipe, an sshd session without a pty) nothing is
  printed and the full `timeout=` budget still applies;
- `phone=off` and `DEUNLOCK_OFF=1` skip the phone entirely — no socket, no
  prompt — so a broken pairing degrades to a normal password prompt.

Budgets: 6 s for the phone side when typing is possible (measured: ~4 s from
notification to sensor on the reference phone), the existing 27 s when it is
not, `choice=<ms>` to override.

Evidence — `crates/deunlock-pam/tests/choice_pty.rs`, five tests over a real
`openpty` pair, no mocks standing in for the terminal:

```
test password_first_wins_and_cancels_the_challenge ... ok
     typed line returned, prompt printed, password absent from the terminal and
     from the request frame, daemon saw the socket close, echo restored
test phone_first_wins_and_discards_what_was_typed ... ok
     verdict is the phone's; the half-typed line is gone from the queue
test neither_side_answers_returns_the_deadline_with_a_clean_terminal ... ok
     1.0 s window honoured, line closed, echo on again, terminal still usable
test phone_off_touches_neither_the_daemon_nor_the_terminal ... ok
     zero connections, no prompt
test deunlock_off_in_the_environment_disables_the_phone ... ok
```

`crates/deunlock-pam/tests/pam_choice_e2e.rs` (gated on `DEUNLOCK_E2E=1`) asks
the same question of the installed module inside the production `sudo` stack
and types a deliberately wrong password: the choice line must appear, no second
`Password:` prompt may follow (proving `pam_unix` read `PAM_AUTHTOK`), and the
attempt must fail (proving `PAM_IGNORE`, not `PAM_SUCCESS`).

Suite: `cargo test --workspace -j 3` → 649 passed, 0 failed, 11 ignored;
`cargo clippy --workspace --all-targets -j 3 -- -D warnings` clean. Three
`redundant_closure` warnings in `runtime.rs` / `pair_code.rs` / `pair_qr.rs`
surfaced under the current clippy and were fixed in passing — no behaviour
change.

Live, on the installed stack (2026-11-12 12:03, module rebuilt from this tree,
`deunlock-presenced` restarted on the same build):

```
$ ( sleep 1; echo <deliberately wrong> ) | script -qec "pamtester sudo roma authenticate" /dev/null
Confirm on your phone, or type your password:
pamtester: Authentication failure
```

One line, no second `Password:` prompt, and the password was deliberately wrong.
That triple is the whole claim: `pam_unix` read the token out of `PAM_AUTHTOK`
(it never asked again), the module did not authenticate anything itself
(`PAM_IGNORE`, not `PAM_SUCCESS`), and nothing was echoed. The daemon, in the
same second:

```
12:03:51 INFO notify_challenge: writing frame peer_id=14f3a566… bytes=105
12:03:52 INFO pam caller hung up mid-challenge; challenge abandoned
```

`tests/pam_choice_e2e.rs` asserts those three properties and passes in 3.39 s
(1 s of typing plus pam_unix's failure delay) against the installed module; run
it with `DEUNLOCK_E2E=1`.

### W-2 — measured before wiring: this machine's lock screen is not `lightdm-greeter`

The plan said "`lightdm-greeter` (lock screen) wired first". Measured on this
machine (2026-11-12), that is wrong twice over:

```
$ cat /etc/X11/default-display-manager            → /usr/sbin/lightdm
$ loginctl show-session c1 -p Desktop -p Type     → Desktop=cinnamon, Type=x11, TTY=tty7
$ cat /etc/pam.d/lightdm-greeter                  → auth required pam_permit.so
$ cat /etc/pam.d/cinnamon-screensaver             → @include common-auth
$ dpkg -L cinnamon-screensaver | grep pam-helper   → /usr/libexec/cinnamon-screensaver/cinnamon-screensaver-pam-helper
```

`lightdm-greeter` authenticates the *greeter* process (`pam_permit`: it is how
the greeter gets to run as its own user) — it is not the user's unlock. The
locked session is Cinnamon's screensaver, which authenticates through its own
service file, `cinnamon-screensaver`, from a helper process. Wired first should
be `cinnamon-screensaver`; `lightdm` stays the login-screen target.

The helper's strings contain no `PAM_TTY`: a GUI stack hands the module a
service name (or nothing), never the terminal a human is typing on. That is why
the module now refuses the terminal choice for such a caller instead of falling
back to `/dev/tty` — on an X session `/dev/tty` is the VT the X server owns, so
a prompt printed there is invisible and a read races the application that does
own the keystrokes (AUDIT-001 W-1; `tests/choice_pty.rs::a_gui_stack_gets_no_prompt_and_the_full_phone_budget`).

One consequence is unavoidable and belongs to the operator, not to the module:
the screensaver collects the password itself and only hands it to the stack when
a module asks. So the phone deadline is also how long an already-typed password
waits. On this machine the owner chose the full 25 s budget for the lock screen.

### D-28 (medium) — an answer to a withdrawn challenge poisoned the next one, CLOSED

Found live, minutes after the first lock-screen unlock, in the exact sequence
W-1 creates: type a password instead of touching the sensor, then run another
`sudo` and touch the sensor for the prompt that is still on the phone.

```
12:24:37 INFO notify_challenge: writing frame peer_id=14f3a566… bytes=105   ← attempt 1
12:24:38 INFO pam caller hung up mid-challenge; challenge abandoned         ← I typed a password
12:24:40 INFO notify_challenge: writing frame peer_id=14f3a566… bytes=105   ← attempt 2
12:24:45 WARN bad signature: operands dumped for offline comparison …       ← the answer to attempt 1
```

The phone's answer is **64 bytes and never names the question it answers**, so
the daemon had no way to tell "the owner is answering the prompt I withdrew a
second ago" from "somebody is forging a signature". It took the first answer on
the wire, verified it against the challenge it was waiting on, and failed closed
with `bad-signature`. Effect: unlock the phone, touch the sensor, get `denied` —
and with `sufficient` the stack then falls back to the password.

Fix: the daemon now keeps the last [`ISSUED_ANSWER_KEEP`] challenges it issued
per peer (the exact bytes the phone signs, with an [`ISSUED_ANSWER_TTL`]) and,
*when verification fails*, asks whether the signature verifies against one of
them. If it does, that is a late answer to a challenge nobody is waiting for any
more: log it, ignore it, keep waiting for the answer to the challenge that is
actually open. If it verifies against nothing we issued, the verdict is still
`bad-signature` — the ignore path cannot accept anything, because a signature
that verifies against the current challenge never reaches it.

Measured in `crates/deunlock-presenced/tests/stale_answer.rs` (3 tests):

```
# with the fix
an_answer_to_an_abandoned_challenge_is_ignored_not_denied ... ok   → Ok
a_late_answer_never_turns_into_a_timeout_free_success ……… ok   → TimedOut, never Ok
a_signature_that_belongs_to_no_challenge_still_fails_closed ok   → BadSignature
# with the stale check disabled (old behaviour), same file:
…ignored_not_denied … FAILED  → got BadSignature
…timeout_free_success … FAILED → got BadSignature
…still_fails_closed … ok       (the path that must NOT relax)
```

The underlying cause — the phone showing a prompt for a challenge the desktop
abandoned — is still D-27's open half: withdrawing it needs a desktop→phone frame
and a phone-side handler. This fix makes the desktop honest about it in the
meantime: a withdrawn prompt's answer is discarded instead of denying the live one.

### D-29 (closed, not a defect) — the two "panics" were the test suite

```
Nov 12 12:11:19 pam_deunlock[…]: deunlock: unlock unavailable reason=panic
Nov 12 12:14:42 pam_deunlock[…]: deunlock: unlock unavailable reason=panic
Nov 12 12:32:25 pam_deunlock[…]: deunlock: unlock unavailable reason=panic
Nov 12 12:34:53 pam_deunlock[…]: deunlock: unlock unavailable reason=panic detail=simulated bug
```

`entry.rs::run_entry_panic_boundary` panics with `simulated bug` on purpose, and
`log_info` wrote that to the auth log from *every* `cargo test -p deunlock-pam`
run: the timestamps match the test runs exactly, and the `detail=` field added
while chasing it (`184d0e7`) names the message. No production invocation ever
panicked.

Two things changed anyway, because both made the confusion possible:

* the panic boundary now logs the payload, so the next real panic names the
  `expect` that fired (`entry.rs::a_panic_message_is_kept_as_one_log_token`);
* `log_info` is silent under `cfg!(test)`, so a passing test run can no longer
  look like a production incident. The integration tests that grep the journal
  run the built `.so`, where `cfg!(test)` is false.

### D-30 (low, CLOSED) — the 6 s window was shorter than picking up a phone

The first `sudo` after the lock screen was wired, measured:

```
12:37:41.41 INFO notify_challenge: writing frame …      ← the phone rings
12:37:47.41 INFO pam caller hung up mid-challenge      ← exactly 6.0 s later
12:37:47    pam_deunlock: reason=choice-deadline tty=/dev/pts/2
```

Six seconds was the budget for a phone *already in hand* (~4 s measured), not
for the real gesture: notification, pick the phone up, unlock it, touch the
sensor. The window expired while the prompt was still on the phone, `sudo`
printed its own password prompt, and the operator typed his password — after
which the phone's approval arrived with nobody waiting (D-27's open half, now
harmless thanks to D-28).

`DEFAULT_CHOICE_WINDOW` is 25,000 ms — the operator's number, and the same one
the lock screen uses. It is coherent with the far end: the phone's approval
prompt counts down from 30 s (`DEFAULT_TIMEOUT_MILLIS` in `ApproveViewModel`), so
the desktop no longer gives up while the prompt is still on the screen. A typist
pays nothing — typing wins immediately — and the window is still clipped by
`timeout=` (27 s for `sudo`) and overridable per service with `choice=<ms>`.

### W-1 — the choice, end to end on the live `sudo`

Installed module `e4f6c925…` (byte-identical to `target/release/libpam_deunlock.so`),
`/etc/pam.d/sudo` unchanged apart from the line that was already there:

```
12:44:33 pam_deunlock[…]: deunlock: unlock success reason=granted
         peer_id=14f3a566465f2d29c16564ef2be12fd9 tty=/dev/pts/2
12:48:00 pam_deunlock[…]: deunlock: unlock success reason=granted
         peer_id=14f3a566465f2d29c16564ef2be12fd9 tty=/dev/pts/3
```

Two `sudo` invocations, two phone approvals, no password typed. The window is
25,000 ms (D-30), the daemon abandons a cancelled challenge (D-27) and ignores a
late answer to one (D-28).

### D-31 (medium) — the phone kept showing the first challenge, CLOSED in code

`ChallengeApprovalActivity` is `launchMode="singleInstance"` + `noHistory="true"`,
so the service's next `PendingIntent.getActivity` does not create an instance: it
delivers `onNewIntent` to the live one. The activity had no `onNewIntent` and
called `setContent` only from `onCreate`, so a second challenge that arrived while
a prompt was already up was dropped — the operator approved the *first* frame
while the desktop was waiting on the second. That is the phone half of the story
whose desktop half is D-28: the same live sequence (`notify` … typed password …
`notify` … `bad signature`) produces both.

Measured twice on the device that the *ordinary* path is fine (two challenges
seconds apart each produced `render` + `Displayed … ChallengeApprovalActivity`,
task ids 8300 → 8301) — but only because the first prompt had already finished
its dwell and called `finish()`. The live-instance path is the one that was
broken, and it is pinned by a test rather than by a screenshot:
`ChallengeApprovalActivityTest.a_second_challenge_replaces_the_prompt` drives
`controller.newIntent(...)` on a resumed activity and asserts the prompt, the peer
id and — the part that matters — the *signed challenge bytes* switch to the second
one.

```
# with the fix
a_second_challenge_replaces_the_prompt … ok      (139 Android unit tests, 0 failures)
# with onNewIntent disabled (the old behaviour):
a_second_challenge_replaces_the_prompt … FAILED  (BUILD FAILED)
```

The activity now renders from a `MutableState` and rebinds on `onNewIntent`,
logging `re-render peer=… superseded=…`. The superseded challenge needs no
answer: its caller has already abandoned it.

### D-31 — the fix, measured on the device

Installed `…/app-debug.apk` (built 13:10) over Wi-Fi. To make the overlap happen
the first caller was killed after one second, so its challenge was abandoned
while the prompt was still on the phone:

```
13:20:31.059 daemon  notify_challenge …                      (challenge I)
13:20:32.056 daemon  pam caller hung up mid-challenge         (I abandoned)
13:20:30.162 phone   render peer=04:EA:56… host=deunlock       (I on screen)
13:20:33.043 phone   render peer=04:EA:56… host=deunlock       (J bound)
13:20:33.043 phone   re-render peer=04:EA:56… superseded=04:EA:56…
13:20:34.061 daemon  notify_challenge …                      (challenge J)
```

The second challenge no longer sits behind the first: the live instance rebinds
and says so. (The phone's clock runs ~1 s behind the desktop's; the two lines at
:33.043 are `bind()`'s own log followed by `onNewIntent`'s.)

### D-32 (medium, OPEN) — rebinding while an approval is already in flight

The same run exposed the next layer, and it is worth stating plainly because it
is the operator-visible end of this sequence:

```
13:20:34.834 daemon  ignoring an answer to a challenge that is no longer open
13:20:59.063 daemon  tx … outcome=response-timeout
```

The operator's tap landed on prompt I (the one he was looking at when he reached
for the sensor); by the time the Keystore callback fired, the screen had rebound
to J. The signature therefore answered I — correctly recognised as stale by D-28
and ignored — and J timed out with nothing to show for the tap.

So after D-31 the *screen* follows the newest challenge, but an approval that is
already running does not: it commits to the frame it started with (which is the
right security behaviour — one biometric, one challenge) and leaves the new one
unanswered. The fix belongs on the phone: on rebind, if a biometric/approve flow
is in flight, cancel it and present the new challenge fresh, instead of letting
one tap be spent on a prompt that no longer exists.
