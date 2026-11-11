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
