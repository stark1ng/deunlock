/* Journey: specs/journeys/JOURNEY-documentation-site.md
 * Original illustrated explainers. No authentication or real device traffic.
 */
(() => {
  "use strict";

  const NS = "http://www.w3.org/2000/svg";
  const STEP_MS = 4800;
  const PORTRAIT_BELOW_PX = 800;
  const scriptUrl = document.currentScript.src;
  const mascot = new URL("../assets/deunlock.png", scriptUrl).href;
  let instance = 0;

  const flows = {
    unlock: {
      title: "One request, one approval", label: "THE UNLOCK EXCHANGE",
      actors: ["terminal", "daemon", "phone"],
      steps: [
        ["Request", "PAM sends a challenge request to the presence daemon through its Unix socket.", ["terminal", "daemon"], "rpc"],
        ["Fresh challenge", "The daemon generates a fresh 16-byte nonce and sends a versioned challenge with a 16-byte BLAKE3 MAC over the subscribed BLE link.", ["daemon", "phone"], "challenge"],
        ["Your approval", "The phone shows the request. You tap Approve, then complete a fresh strong biometric check.", ["phone"], null],
        ["Keystore signs", "The phone's Ed25519 key signs the challenge body, excluding the MAC. The private key stays in Android Keystore.", ["phone"], null],
        ["Signature returns", "The phone writes the raw 64-byte signature to the desktop's response characteristic.", ["phone", "daemon"], "response"],
        ["Verify and remember", "The daemon verifies the signature with the bonded phone public key, checks its recent-nonce replay cache, then records the accepted nonce.", ["daemon"], null],
        ["PAM result", "PAM maps the daemon's result. The calling application's PAM stack decides access and password fallback.", ["daemon", "terminal"], "result"],
      ],
    },
    pairing: {
      title: "Meet once, compare twice", label: "PAIRING & IDENTITY",
      actors: ["desktop", "phone"],
      steps: [
        ["Find the desktop", "The desktop advertises its pairing service. The phone selects it through CompanionDeviceManager and connects using Bluetooth LE.", ["desktop", "phone"], "discovery"],
        ["Compare six digits", "Compare the six-digit Bluetooth numeric value on both devices and confirm it. The displayed numbers here are examples.", ["desktop", "phone"], null],
        ["Read host public key", "The phone reads the desktop's public key before sending its own public key.", ["desktop", "phone"], "host-key"],
        ["Write phone public key", "The phone writes its Keystore Ed25519 public key to the desktop. Its private signing key is not exported.", ["phone", "desktop"], "phone-key"],
        ["Derive application material", "Both sides derive bond material with HKDF-SHA256 from the two public keys. This public-input derivation is not a confidential key exchange.", ["desktop", "phone"], null],
        ["Compare four words", "Compare and confirm the separate four-word application code on both devices. The words in this illustration are examples.", ["desktop", "phone"], null],
        ["Save the bond", "Both sides retain their bond information. The phone's companion association supports later discovery; pairing never approves an unlock.", ["desktop", "phone"], "saved"],
      ],
    },
    discovery: {
      title: "Find each other, then stay ready", label: "DISCOVERY & CONNECTION",
      actors: ["desktop", "phone"],
      steps: [
        ["Minute changes", "The daemon derives a session UUID with HKDF-SHA256 using bond material and the current minute.", ["desktop"], null],
        ["Advertise UUID", "The desktop advertises the derived rendezvous UUID over Bluetooth LE; the session UUID changes each minute.", ["desktop", "phone"], "advertisement"],
        ["Match nearby desktop", "The phone computes UUIDs for the current and previous minute and matches the desktop advertisement.", ["phone"], null],
        ["Connect with LE", "The persistent GATT client reconnects to the remembered desktop using explicit LE transport and autoConnect.", ["phone", "desktop"], "connect"],
        ["Subscribe", "The phone discovers services and enables challenge notifications through the CCCD. Connected alone does not mean ready.", ["phone", "desktop"], "subscribe"],
        ["Ready for a request", "After subscription, the desktop can deliver a fresh challenge. Being nearby never grants access: each unlock still needs approval and biometrics.", ["desktop", "phone"], "ready"],
      ],
    },
  };

  function html(tag, className, value) {
    const node = document.createElement(tag);
    node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }

  function svg(tag, attrs, parent) {
    const node = document.createElementNS(NS, tag);
    for (const [name, value] of Object.entries(attrs || {})) node.setAttribute(name, String(value));
    if (parent) parent.append(node);
    return node;
  }

  function text(parent, x, y, value, className = "", attrs = {}) {
    const node = svg("text", {x, y, class: className, ...attrs}, parent);
    node.textContent = value;
    return node;
  }

  function lines(parent, x, y, value, compact) {
    const words = value.split(" ");
    const limit = compact ? 44 : 100;
    let line = "";
    let offset = 0;
    for (const word of words) {
      if (line.length + word.length > limit) {
        text(parent, x, y + offset, line, "sy-svg-small sy-muted", {"text-anchor": "middle"});
        offset += 22;
        line = "";
      }
      line += (line ? " " : "") + word;
    }
    text(parent, x, y + offset, line, "sy-svg-small sy-muted", {"text-anchor": "middle"});
  }

  function rect(parent, x, y, width, height, className, radius = 10, attrs = {}) {
    return svg("rect", {x, y, width, height, rx: radius, class: className, ...attrs}, parent);
  }

  function group(parent, x = 0, y = 0, attrs = {}) {
    return svg("g", {transform: "translate(" + x + " " + y + ")", ...attrs}, parent);
  }

  function path(parent, d, className, attrs = {}) {
    return svg("path", {d, class: className, ...attrs}, parent);
  }

  function icon(parent, kind, x, y, size = 28, className = "") {
    const node = group(parent, x, y, {class: "sy-icon " + className, transform: "translate(" + x + " " + y + ") scale(" + size / 32 + ")"});
    const shapes = {
      terminal: ["M3 5h26v20H3z", "M10 30h12M16 25v5", "M8 11l4 4-4 4m8 0h7"],
      daemon: ["M5 3h22v10H5zM5 19h22v10H5z", "M9 8h1m5 0h8M9 24h1m5 0h8M16 13v6"],
      key: ["M14 18a8 8 0 1 1 4-4l12 12-4 4-4-4v-4h-4z"],
      shield: ["M16 2l12 5v9c0 7-12 14-12 14S4 23 4 16V7z", "M10 16l4 4 8-9"],
      bluetooth: ["M16 2v28l9-8L7 9m9-7 9 8L7 23"],
      clock: ["M16 2a14 14 0 1 0 0 28 14 14 0 0 0 0-28", "M16 8v9l7 4"],
      fingerprint: ["M5 20v-5a11 11 0 0 1 22 0v5", "M9 23v-8a7 7 0 0 1 14 0v8", "M13 26V15a3 3 0 0 1 6 0v12", "M16 15v15M5 24l1 4m19-4-1 4M2 15a14 14 0 0 1 28 0"],
      check: ["M5 17l7 7L28 7"],
    };
    for (const d of shapes[kind] || []) path(node, d, "sy-icon__stroke");
    return node;
  }

  function pill(parent, x, y, width, value, kind = "") {
    rect(parent, x, y, width, 30, "sy-pill " + kind, 15);
    text(parent, x + width / 2, y + 20, value, "sy-svg-small " + kind, {"text-anchor": "middle"});
  }

  function check(parent, x, y, value, accepted) {
    const node = group(parent, x, y, {"data-visible": String(accepted), class: "sy-verification"});
    icon(node, "check", 0, -15, 19, "sy-good");
    text(node, 28, 0, value, "sy-svg-body sy-good");
  }

  function fingerprint(parent, x, y, active, size = 66) {
    const node = group(parent, x, y, {"data-part": "fingerprint", "data-active": String(active), class: "sy-fingerprint"});
    svg("circle", {cx: size / 2, cy: size / 2, r: size / 2 + 7, class: "sy-fingerprint__ring"}, node);
    icon(node, "fingerprint", 0, 0, size);
    path(node, "M0 " + size / 2 + "h" + size, "sy-fingerprint__scan");
  }

  function device(parent, type, box, active, phone = false) {
    const node = group(parent, box.x, box.y, {"data-node": type, "data-active": String(active), class: "sy-device"});
    rect(node, 0, 0, box.w, box.h, "sy-device__body", phone ? 22 : 12);
    rect(node, 7, 7, box.w - 14, box.h - 14, "sy-device__screen", phone ? 17 : 7);
    if (phone) {
      rect(node, box.w / 2 - 23, 10, 46, 5, "sy-phone__speaker", 3);
      svg("image", {href: mascot, x: 17, y: 20, width: 30, height: 30}, node);
      text(node, 53, 42, "deunlock", "sy-svg-body");
      rect(node, box.w / 2 - 21, box.h - 13, 42, 3, "sy-phone__speaker", 2);
    } else {
      svg("circle", {cx: 20, cy: 20, r: 3, class: "sy-dot sy-pink"}, node);
      svg("circle", {cx: 32, cy: 20, r: 3, class: "sy-dot sy-gold"}, node);
      svg("circle", {cx: 44, cy: 20, r: 3, class: "sy-dot sy-good"}, node);
      path(node, "M10 33H" + (box.w - 10), "sy-device__separator");
    }
    return node;
  }

  function boundary(parent, x, y, width, height, label) {
    rect(parent, x, y, width, height, "sy-boundary", 16);
    text(parent, x + 14, y + 24, label, "sy-svg-kicker");
  }

  function channel(parent, id, route, label, labelX, labelY, visible, active, marker, number) {
    const node = svg("g", {"data-channel": id, "data-visible": String(visible), "data-active": String(active), class: "sy-channel"}, parent);
    const line = path(node, route, "sy-channel__line", {"marker-end": "url(#" + marker + ")"});
    if (active) line.classList.add("sy-channel__line--active");
    rect(node, labelX - 12, labelY - 17, Math.min(260, label.length * 8 + 42), 25, "sy-channel__label-bg", 5);
    text(node, labelX, labelY, number + "  " + label, "sy-svg-small");
    return line;
  }

  function packet(parent, line, label, compact) {
    const node = group(parent, 0, 0, {"data-packet": "", class: "sy-mechanics__packet"});
    const short = compact || line.getTotalLength() < 150;
    const abbreviations = {"nonce + MAC": "N+M", signature: "SIG", challenge: "RPC", "host pubkey": "HK", "phone pubkey": "PK", "7f2e…b961": "UUID", "LE connect": "LE", "CCCD = 1": "CCCD", association: "CDM"};
    rect(node, short ? -24 : -69, -15, short ? 48 : 138, 30, "sy-packet__body", 6);
    if (!short) path(node, "M-59-6l10 7 10-7M-59-6v13h20V-6", "sy-packet__envelope");
    text(node, short ? 0 : 9, 5, short ? abbreviations[label] || label : label, "sy-packet__text", {"data-message": label, "text-anchor": "middle"});
    return {node, line};
  }

  function wireFrame(parent, x, y, width, signing) {
    const node = group(parent, x, y, {"data-part": "challenge", class: "sy-frame"});
    text(node, 0, 0, signing ? "SIGN THE BODY" : "THE CHALLENGE · 33 BYTES", "sy-svg-kicker");
    const unit = width / 6;
    rect(node, 0, 14, unit, 44, "sy-frame__version", 5);
    rect(node, unit + 4, 14, unit * 3 - 8, 44, "sy-frame__nonce", 5, {"data-part": "nonce"});
    rect(node, unit * 4, 14, unit * 2, 44, "sy-frame__mac", 5, {"data-part": "mac"});
    text(node, unit / 2, 41, "v1", "sy-svg-body", {"text-anchor": "middle"});
    text(node, unit * 2.5, 41, "nonce · 16 B", "sy-svg-body sy-pink", {"text-anchor": "middle"});
    text(node, unit * 5, 41, "MAC · 16 B", "sy-svg-body sy-gold", {"text-anchor": "middle"});
    if (signing) {
      path(node, "M0 66v6H" + (unit * 4 - 4) + "v-6", "sy-frame__bracket");
      text(node, unit * 2, 94, "Ed25519 signs these bytes", "sy-svg-small sy-pink", {"text-anchor": "middle"});
      text(node, unit * 5, 94, "not signed", "sy-svg-small sy-muted", {"text-anchor": "middle"});
    }
  }

  function signature(parent, x, y, width) {
    const node = group(parent, x, y, {"data-part": "signature", class: "sy-signature"});
    text(node, 0, 0, "THE RESPONSE · RAW SIGNATURE", "sy-svg-kicker");
    rect(node, 0, 14, width, 48, "sy-signature__body", 6);
    for (let n = 0; n < 24; n++) rect(node, 12 + n * (width - 24) / 24, 25, 3 + n % 3, 21, "sy-signature__bit", 1);
    rect(node, width / 2 - 85, 23, 170, 28, "sy-signature__label", 4);
    text(node, width / 2, 43, "Ed25519 · 64 B", "sy-svg-body sy-good", {"text-anchor": "middle"});
  }

  function phoneKeystore(parent, width, height, active) {
    const key = group(parent, 12, height - 66, {"data-part": "keystore", "data-active": String(active), class: "sy-keystore"});
    rect(key, 0, 0, width - 24, 43, "sy-keystore__boundary", 6);
    icon(key, "key", 10, 9, 24, "sy-gold");
    text(key, 42, 19, "Android Keystore", "sy-svg-small");
    text(key, 42, 35, "Key not exported", "sy-svg-tiny sy-muted");
  }

  function unlockScene(scene, step, compact, flow, marker) {
    const boxes = compact
      ? {terminal: {x: 20, y: 58, w: 176, h: 166}, daemon: {x: 224, y: 58, w: 176, h: 166}, phone: {x: 112, y: 332, w: 196, h: 302}}
      : {terminal: {x: 32, y: 82, w: 204, h: 220}, daemon: {x: 352, y: 82, w: 226, h: 220}, phone: {x: 718, y: 52, w: 208, h: 316}};
    const focus = flow.steps[step][2];
    boundary(scene, compact ? 8 : 16, compact ? 15 : 24, compact ? 404 : 580, compact ? 230 : 302, "LINUX · LOCAL AUTHENTICATION");
    const terminal = device(scene, "terminal", boxes.terminal, focus.includes("terminal"));
    const tw = boxes.terminal.w;
    text(terminal, 16, 58, "$ sudo -v", "sy-svg-mono");
    text(terminal, 16, 86, step === 6 ? "PAM_SUCCESS" : "pam_deunlock.so", "sy-svg-body " + (step === 6 ? "sy-good" : ""));
    text(terminal, 16, 113, step === 6 ? "Apply PAM policy" : "Authenticate…", "sy-svg-small sy-muted");
    if (step === 6) icon(terminal, "check", tw - 48, 124, 28, "sy-good");
    else text(terminal, 16, compact ? 140 : 161, "Waiting for phone", "sy-svg-tiny sy-muted");

    const daemon = device(scene, "daemon", boxes.daemon, focus.includes("daemon"));
    icon(daemon, "daemon", 16, 47, 30, "sy-gold");
    text(daemon, 54, 59, compact ? "Presence" : "Presence daemon", "sy-svg-body");
    text(daemon, 16, 94, ["Select bonded peer", "Generate nonce", "Await approval", "Await signature", "Response received", "Check the proof", "reason = ok"][step], "sy-svg-small");
    if (step >= 5) {
      check(daemon, 16, compact ? 121 : 138, "Signature valid", true);
      check(daemon, 16, compact ? 148 : 171, "Nonce unseen", true);
    } else {
      text(daemon, 16, compact ? 125 : 140, "1 challenge / peer", "sy-svg-small sy-muted");
      if (!compact) text(daemon, 16, 176, "Pinned phone public key", "sy-svg-small sy-muted");
    }

    const phone = device(scene, "phone", boxes.phone, focus.includes("phone"), true);
    text(phone, boxes.phone.w / 2, 76, "my-desktop", "sy-svg-body", {"text-anchor": "middle"});
    text(phone, boxes.phone.w / 2, 101, ["Ready for requests", "Request received", "Approve", "Biometric verified", "Signature sent", "Signature sent", "Signature sent"][step], "sy-svg-small " + (step >= 3 ? "sy-good" : ""), {"text-anchor": "middle"});
    fingerprint(phone, boxes.phone.w / 2 - 30, 119, step === 2, 60);
    if (step === 2) pill(phone, boxes.phone.w / 2 - 52, 202, 104, "Approve", "sy-pink");
    else text(phone, boxes.phone.w / 2, 213, step === 3 ? "sign(body)" : step >= 4 ? "64-byte response" : "Fresh biometric", "sy-svg-small sy-muted", {"text-anchor": "middle"});
    phoneKeystore(phone, boxes.phone.w, boxes.phone.h, step === 3);

    const routes = compact ? [
      ["rpc", "M196 140H224", "Unix socket", 133, 268, 0, 1],
      ["challenge", "M312 224V278Q312 290 300 290H210V332", "Notify challenge", 183, 316, 1, 2],
      ["response", "M308 540H380Q396 540 396 524V224", "Write signature", 235, 571, 4, 3],
      ["result", "M224 195H196", "PAM result", 30, 295, 6, 4],
    ] : [
      ["rpc", "M236 146H352", "Unix socket", 246, 127, 0, 1],
      ["challenge", "M578 154H718", "BLE notify", 589, 129, 1, 2],
      ["response", "M718 267H578", "BLE write", 588, 297, 4, 3],
      ["result", "M352 249H236", "PAM result", 246, 281, 6, 4],
    ];
    let moving = null;
    for (const [id, d, label, lx, ly, first, number] of routes) {
      const active = flow.steps[step][3] === id;
      const line = channel(scene, id, d, label, lx, ly, step >= first, active, marker, number);
      if (active) moving = {line, label: id === "challenge" ? "nonce + MAC" : id === "response" ? "signature" : id === "result" ? "ok" : "challenge"};
    }
    const detailY = compact ? 690 : 397;
    const detailW = compact ? 372 : 870;
    if (step < 4) wireFrame(scene, compact ? 24 : 45, detailY, detailW, step === 3);
    else signature(scene, compact ? 24 : 45, detailY, detailW);
    if (step >= 5) text(scene, compact ? 210 : 480, compact ? 802 : 483, "Original body + pinned public key + signature", "sy-svg-small sy-muted", {"text-anchor": "middle"});
    return moving;
  }

  function pairedDesktop(parent, box, step, active) {
    const desktop = device(parent, "desktop", box, active);
    icon(desktop, "terminal", 17, 47, 29, "sy-gold");
    text(desktop, 56, 65, "Linux desktop", "sy-svg-body");
    text(desktop, 18, 100, "$ deunlock pair", "sy-svg-mono");
    if (step === 1) {
      text(desktop, box.w / 2, 150, "418 206", "sy-svg-code", {"text-anchor": "middle"});
      text(desktop, box.w / 2, 182, "Compare both screens", "sy-svg-small sy-pink", {"text-anchor": "middle"});
    } else if (step === 5) {
      text(desktop, 18, 142, "cat · moon", "sy-svg-body sy-pink");
      text(desktop, 18, 172, "leaf · star", "sy-svg-body sy-pink");
    } else if (step === 6) {
      check(desktop, 18, 144, "Phone identity pinned", true);
      text(desktop, 18, 179, "bonds.toml", "sy-svg-mono sy-muted");
    } else {
      text(desktop, 18, 141, step >= 4 ? "HKDF-SHA256" : "Host public key", "sy-svg-body");
      pill(desktop, 18, 161, box.w - 36, step >= 4 ? "bond material · 32 B" : "host pubkey · 32 B", "sy-gold");
    }
    return desktop;
  }

  function pairingScene(scene, step, compact, flow, marker) {
    const a = compact ? {x: 57, y: 52, w: 306, h: 218} : {x: 42, y: 88, w: 310, h: 236};
    const b = compact ? {x: 108, y: 399, w: 204, h: 314} : {x: 714, y: 48, w: 210, h: 330};
    boundary(scene, compact ? 40 : 20, compact ? 10 : 22, compact ? 340 : 355, compact ? 279 : 324, "LINUX · GATT PERIPHERAL");
    pairedDesktop(scene, a, step, flow.steps[step][2].includes("desktop"));
    const phone = device(scene, "phone", b, flow.steps[step][2].includes("phone"), true);
    text(phone, b.w / 2, 79, "Pair with computer", "sy-svg-body", {"text-anchor": "middle"});
    if (step === 1) {
      text(phone, b.w / 2, 130, "418 206", "sy-svg-code", {"text-anchor": "middle"});
      pill(phone, 28, 164, b.w - 56, "Codes match", "sy-pink");
    } else if (step === 5) {
      text(phone, b.w / 2, 125, "cat · moon", "sy-svg-body sy-pink", {"text-anchor": "middle"});
      text(phone, b.w / 2, 157, "leaf · star", "sy-svg-body sy-pink", {"text-anchor": "middle"});
      pill(phone, 28, 188, b.w - 56, "Words match", "sy-pink");
    } else if (step === 6) {
      icon(phone, "shield", b.w / 2 - 30, 110, 60, "sy-good");
      text(phone, b.w / 2, 202, "Bond saved", "sy-svg-body sy-good", {"text-anchor": "middle"});
    } else {
      icon(phone, step === 0 ? "bluetooth" : "key", b.w / 2 - 26, 111, 52, step >= 4 ? "sy-pink" : "sy-gold");
      text(phone, b.w / 2, 193, step >= 4 ? "HKDF-SHA256" : "phone pubkey · 32 B", "sy-svg-small", {"data-part": "public-key", "text-anchor": "middle"});
    }
    phoneKeystore(phone, b.w, b.h, step === 3);

    const routes = compact ? [
      ["discovery", "M210 270V399", "LESC pairing", 224, 310, 0, 1],
      ["host-key", "M147 270V399", "Read host key first", 21, 352, 2, 2],
      ["phone-key", "M273 399V270", "Then write phone key", 177, 378, 3, 3],
      ["saved", "M108 621H40V270", "Remember identity", 25, 749, 6, 4],
    ] : [
      ["discovery", "M352 130H714", "LESC · numeric comparison", 393, 110, 0, 1],
      ["host-key", "M352 202H714", "Read host public key", 397, 181, 2, 2],
      ["phone-key", "M714 276H352", "Write phone public key", 397, 310, 3, 3],
      ["saved", "M714 350H393Q380 350 380 337V320", "Companion association", 414, 379, 6, 4],
    ];
    let moving = null;
    for (const [id, d, label, lx, ly, first, number] of routes) {
      const active = flow.steps[step][3] === id;
      const line = channel(scene, id, d, label, lx, ly, step >= first, active, marker, number);
      if (active) moving = {line, label: id === "host-key" ? "host pubkey" : id === "phone-key" ? "phone pubkey" : id === "saved" ? "association" : "pair"};
    }
    const y = compact ? 798 : 432;
    if (step === 4) {
      const node = group(scene, compact ? 20 : 65, y - 14, {"data-part": "public-key"});
      rect(node, 0, 0, compact ? 380 : 830, 62, "sy-formula", 8);
      text(node, compact ? 190 : 415, 24, "HKDF(host pubkey || phone pubkey)", "sy-svg-mono", {"text-anchor": "middle"});
      text(node, compact ? 190 : 415, 48, "Public inputs ≠ confidential key exchange", "sy-svg-small sy-pink", {"text-anchor": "middle"});
    } else {
      lines(scene, compact ? 210 : 480, y, step === 1 ? "FIRST CHECK · Bluetooth numeric comparison" : step === 5 ? "SECOND CHECK · Application code comparison" : step === 6 ? "Identity remembered. Every unlock still needs approval." : "Read host key → write phone key → compare application code", compact);
    }
    return moving;
  }

  function waves(parent, x, y, active) {
    const node = group(parent, x, y, {class: "sy-radio", "data-active": String(active)});
    for (let i = 0; i < 3; i++) {
      const r = 17 + i * 17;
      path(node, "M" + r + " " + -r + "Q" + r * 2.2 + " 0 " + r + " " + r, "sy-radio__wave", {style: "--wave:" + i});
    }
  }

  function discoveryScene(scene, step, compact, flow, marker) {
    const a = compact ? {x: 57, y: 52, w: 306, h: 230} : {x: 42, y: 85, w: 310, h: 250};
    const b = compact ? {x: 100, y: 418, w: 220, h: 316} : {x: 704, y: 51, w: 222, h: 324};
    boundary(scene, compact ? 40 : 20, compact ? 10 : 22, compact ? 340 : 355, compact ? 291 : 337, "LINUX · ADVERTISER");
    const desktop = device(scene, "desktop", a, flow.steps[step][2].includes("desktop"));
    icon(desktop, "clock", 18, 50, 34, "sy-pink");
    text(desktop, 65, 65, "Minute n → n + 1", "sy-svg-body");
    text(desktop, 18, 112, "HKDF(K, minute)", "sy-svg-mono");
    pill(desktop, 18, 134, a.w - 36, "7f2e…b961", "sy-gold");
    text(desktop, 18, 194, step >= 5 ? "Notifications ready" : "Rotating rendezvous UUID", "sy-svg-small " + (step >= 5 ? "sy-good" : "sy-muted"));
    if (!compact) waves(scene, 365, 182, step === 1);

    const phone = device(scene, "phone", b, flow.steps[step][2].includes("phone"), true);
    text(phone, b.w / 2, 77, "Find my desktop", "sy-svg-body", {"text-anchor": "middle"});
    text(phone, 16, 112, "Current minute", "sy-svg-small sy-muted");
    pill(phone, 16, 126, b.w - 32, "7f2e…b961", step >= 2 ? "sy-good" : "sy-gold");
    text(phone, 16, 182, "Previous minute", "sy-svg-small sy-muted");
    pill(phone, 16, 196, b.w - 32, "a830…f42c", "");
    text(phone, b.w / 2, 270, step >= 5 ? "Subscribed · ready" : step >= 3 ? "Connected ≠ ready" : step === 2 ? "UUID matches" : "Watching for peer", "sy-svg-small " + (step >= 5 || step === 2 ? "sy-good" : "sy-pink"), {"text-anchor": "middle", "data-part": "uuid"});

    const routes = compact ? [
      ["advertisement", "M210 282V418", "Advertise UUID", 223, 321, 1, 1],
      ["connect", "M137 418V282", "Connect · LE", 15, 360, 3, 2],
      ["subscribe", "M283 418V282", "Enable CCCD", 233, 391, 4, 3],
      ["ready", "M320 667H388V282", "Channel ready", 211, 775, 5, 4],
    ] : [
      ["advertisement", "M352 139H704", "Rotating UUID", 436, 118, 1, 1],
      ["connect", "M704 205H352", "Connect · TRANSPORT_LE", 402, 185, 3, 2],
      ["subscribe", "M704 275H352", "Discover → enable CCCD", 408, 311, 4, 3],
      ["ready", "M352 350H704", "Notifications ready", 429, 385, 5, 4],
    ];
    let moving = null;
    for (const [id, d, label, lx, ly, first, number] of routes) {
      const active = flow.steps[step][3] === id;
      const line = channel(scene, id, d, label, lx, ly, step >= first, active, marker, number);
      if (active) moving = {line, label: id === "advertisement" ? "7f2e…b961" : id === "subscribe" ? "CCCD = 1" : id === "ready" ? "ready" : "LE connect"};
    }
    const y = compact ? 825 : 439;
    lines(scene, compact ? 210 : 480, y, step >= 5 ? "CONNECTED + SUBSCRIBED ≠ AUTHENTICATED" : "The rendezvous rotates. The bonded GATT service stays stable.", compact);
    return moving;
  }

  function drawScene(root, flow, step, compact, uid) {
    const portraitHeight = root.dataset.flow === "unlock" ? 840 : 900;
    const canvas = svg("svg", {class: "sy-scene", "data-layout": compact ? "portrait" : "landscape", viewBox: compact ? "0 0 420 " + portraitHeight : "0 0 960 510", role: "img", "aria-labelledby": uid + "-title " + uid + "-desc"});
    const title = svg("title", {id: uid + "-title"}, canvas);
    title.textContent = flow.title + ": " + flow.steps[step][0];
    const desc = svg("desc", {id: uid + "-desc"}, canvas);
    desc.textContent = flow.steps[step][1] + " Labeled arrows connect the illustrated devices; sample values are not real credentials.";
    const defs = svg("defs", {}, canvas);
    const pattern = svg("pattern", {id: uid + "-grid", width: 24, height: 24, patternUnits: "userSpaceOnUse"}, defs);
    svg("circle", {cx: 1, cy: 1, r: .8, class: "sy-grid-dot"}, pattern);
    rect(canvas, 0, 0, compact ? 420 : 960, compact ? 900 : 510, "", 0, {fill: "url(#" + uid + "-grid)"});
    const marker = svg("marker", {id: uid + "-arrow", viewBox: "0 0 10 10", refX: 8, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse"}, defs);
    path(marker, "M0 0L10 5L0 10z", "sy-arrowhead");
    const renderer = {unlock: unlockScene, pairing: pairingScene, discovery: discoveryScene}[root.dataset.flow];
    const moving = renderer(canvas, step, compact, flow, uid + "-arrow");
    const packetState = moving ? packet(canvas, moving.line, moving.label, compact) : null;
    return {canvas, packetState};
  }

  function mount(root) {
    const flow = flows[root.dataset.flow];
    if (!flow || root.children.length) return;
    const uid = "sy-story-" + ++instance;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
    let step = 0;
    let playing = false;
    let elapsed = 0;
    let lastTime = null;
    let frameId = null;
    let speed = 1;
    let compact = root.clientWidth < PORTRAIT_BELOW_PX;
    let packetState = null;
    root.setAttribute("role", "group");
    root.setAttribute("aria-label", flow.title + " animated explanation");

    const top = html("div", "sy-mechanics__top");
    const kicker = html("span", "sy-story-label", flow.label);
    const sample = html("span", "sy-story-sample", "Animation · example values");
    top.append(kicker, sample);
    const title = html("p", "sy-mechanics__title", flow.title);
    const screen = html("div", "sy-mechanics__screen");
    const progress = html("div", "sy-mechanics__progress");
    progress.setAttribute("aria-hidden", "true");
    const progressFill = html("span", "");
    progress.append(progressFill);
    const chapters = html("div", "sy-chapters");
    chapters.setAttribute("aria-label", "Explanation chapters");
    const chapterButtons = flow.steps.map((entry, index) => {
      const button = html("button", "sy-chapter");
      button.type = "button";
      const number = html("span", "sy-chapter__number", String(index + 1).padStart(2, "0"));
      button.append(number, html("span", "", entry[0]));
      button.addEventListener("click", () => seek(index));
      chapters.append(button);
      return button;
    });
    const stage = html("div", "sy-mechanics__stage");
    stage.setAttribute("aria-live", "polite");
    stage.setAttribute("aria-atomic", "true");
    const counter = html("div", "sy-mechanics__counter");
    const heading = html("strong", "");
    const description = html("p", "");
    stage.append(counter, heading, description);
    const controls = html("div", "sy-mechanics__controls");
    const play = html("button", "sy-play", "Play");
    const previous = html("button", "", "Previous step");
    const next = html("button", "", "Next step");
    const restart = html("button", "", "Restart");
    for (const button of [play, previous, next, restart]) button.type = "button";
    const speedLabel = html("label", "sy-speed", "Playback speed");
    const speedInput = html("select", "");
    speedInput.setAttribute("aria-label", "Playback speed");
    for (const value of ["0.75", "1", "1.5"]) {
      const option = html("option", "", value + "×");
      option.value = value;
      option.selected = value === "1";
      speedInput.append(option);
    }
    speedLabel.append(speedInput);
    controls.append(play, previous, next, restart, speedLabel);
    const note = html("p", "sy-mechanics__motion-note");
    root.append(top, title, screen, progress, chapters, stage, controls, note);

    function pose(fraction) {
      const progress = (step + (reduced.matches ? 1 : fraction)) / flow.steps.length;
      progressFill.style.transform = "scaleX(" + progress + ")";
      if (!packetState) return;
      const {node, line} = packetState;
      const phase = reduced.matches ? 1 : Math.min(1, Math.max(0, (fraction - .08) / .65));
      const length = line.getTotalLength();
      const point = line.getPointAtLength(length * phase);
      node.setAttribute("transform", "translate(" + point.x + " " + point.y + ")");
      node.style.opacity = reduced.matches ? "0" : String(phase > .92 ? (1 - phase) / .08 : 1);
      line.style.strokeDasharray = String(length);
      line.style.strokeDashoffset = String(length * (1 - phase));
    }

    function pause() {
      playing = false;
      window.cancelAnimationFrame(frameId);
      lastTime = null;
      root.dataset.playing = "false";
      play.textContent = "Play";
      play.setAttribute("aria-pressed", "false");
    }

    function render() {
      root.dataset.step = String(step);
      root.dataset.motion = reduced.matches ? "reduced" : "full";
      const {canvas, packetState: moving} = drawScene(root, flow, step, compact, uid);
      screen.replaceChildren(canvas);
      packetState = moving;
      counter.textContent = "Step " + (step + 1) + " of " + flow.steps.length;
      heading.textContent = flow.steps[step][0];
      description.textContent = flow.steps[step][1];
      chapterButtons.forEach((button, index) => {
        button.dataset.complete = String(index < step);
        if (index === step) button.setAttribute("aria-current", "step");
        else button.removeAttribute("aria-current");
      });
      previous.disabled = step === 0;
      next.disabled = step === flow.steps.length - 1;
      play.disabled = next.disabled && !playing && elapsed >= STEP_MS;
      note.textContent = reduced.matches
        ? "Reduced motion: diagrams stay still. Play advances captions; chapters and step controls work at your pace."
        : "Follow the messages, pause to inspect, or choose any chapter. No real device connection.";
      pose(playing ? elapsed / STEP_MS : 1);
    }

    function seek(index) {
      pause();
      step = index;
      elapsed = step === flow.steps.length - 1 ? STEP_MS : 0;
      render();
    }

    function tick(now) {
      if (!playing) return;
      if (lastTime !== null) elapsed += (now - lastTime) * speed;
      lastTime = now;
      if (elapsed >= STEP_MS) {
        if (step === flow.steps.length - 1) {
          elapsed = STEP_MS;
          pause();
          render();
          return;
        }
        elapsed %= STEP_MS;
        step += 1;
        render();
      }
      pose(elapsed / STEP_MS);
      frameId = window.requestAnimationFrame(tick);
    }

    play.addEventListener("click", () => {
      if (playing) return pause();
      playing = true;
      root.dataset.playing = "true";
      play.textContent = "Pause";
      play.setAttribute("aria-pressed", "true");
      lastTime = null;
      pose(elapsed / STEP_MS);
      frameId = window.requestAnimationFrame(tick);
    });
    previous.addEventListener("click", () => {
      seek(Math.max(0, step - 1));
      if (previous.disabled) next.focus();
    });
    next.addEventListener("click", () => {
      seek(Math.min(flow.steps.length - 1, step + 1));
      if (next.disabled) restart.focus();
    });
    restart.addEventListener("click", () => seek(0));
    speedInput.addEventListener("change", () => { speed = Number(speedInput.value); });
    document.addEventListener("visibilitychange", () => { if (document.hidden) pause(); });
    reduced.addEventListener("change", () => { pause(); render(); });
    new ResizeObserver(() => {
      const narrow = root.clientWidth < PORTRAIT_BELOW_PX;
      if (compact !== narrow) { compact = narrow; render(); }
    }).observe(root);
    pause();
    render();
  }

  function initialize() {
    document.querySelectorAll(".sy-mechanics[data-flow]").forEach(mount);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize);
  else initialize();
})();
