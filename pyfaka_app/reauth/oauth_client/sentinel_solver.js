// === Sentinel SDK Solver — 完整浏览器环境模拟 ===
// 所有 API 存根均模拟当前 payload 对应的桌面浏览器行为

// ---- SDK 补丁（同时兼容压缩版和格式化版） ----
const PATCHES = [
  {
    name: "sdk-global",
    required: true,
    find: /var SentinelSDK\s*=/,
    replace: "globalThis.SentinelSDK=",
  },
  {
    name: "auth-client-20260810913b",
    applies: (sdk) => /t\.requirementsToken\s*=\s*function/.test(sdk),
    find: /var E\s*=\s*new O\s*(\(\s*\))?\s*;?/,
    replace: "var E=new O();globalThis.__debugP=E;",
  },
  {
    name: "auth-bindings-20260810913b",
    applies: (sdk) => /t\.requirementsToken\s*=\s*function/.test(sdk),
    find: /t\.timing\s*=\s*function\s*\(\)\s*\{[\s\S]*?return Ae\s*}\s*,\s*t\.token\s*=\s*je/,
    replace: "t.timing=function(){if(ie)throw new Error(Hn(54));return Ae},t.__debug_n=Rn,t.__debug_bindProof=D,t.__debug_bindSO=we,t.__debug_wrap=me,t.token=je",
  },
  {
    name: "chat-client",
    applies: (sdk) => /var q\s*=\s*new _/.test(sdk) && /t\.token\s*=\s*Ie/.test(sdk),
    find: /var q\s*=\s*new _\s*(\(\s*\))?\s*;?/,
    replace: "var q=new _();globalThis.__debugP=q;",
  },
  {
    name: "chat-bindings",
    applies: (sdk) => /var q\s*=\s*new _/.test(sdk) && /t\.token\s*=\s*Ie/.test(sdk),
    find: /t\.token\s*=\s*Ie(?=\s*,\s*t\s*}\(\{\}\))/,
    replace: "t.__debug_bindProof=I,t.__debug_n=(challenge,dx)=>Pn(challenge,dx),t.__debug_bindSO=ke,t.__debug_wrap=ve,t.token=Ie",
  },
  {
    name: "platform-client-2d1db0d5",
    applies: (sdk) => /var Rt\s*=\s*new Ut/.test(sdk) && /t\.token\s*=\s*bn/.test(sdk),
    find: /var Rt\s*=\s*new Ut\s*(\(\s*\))?\s*;?/,
    replace: "var Rt=new Ut();globalThis.__debugP=Rt;",
  },
  {
    name: "platform-bindings-2d1db0d5",
    applies: (sdk) => /var Rt\s*=\s*new Ut/.test(sdk) && /t\.token\s*=\s*bn/.test(sdk),
    find: /t\.token\s*=\s*bn/,
    replace: "t.token=bn,t.__debug_bindProof=(challenge,requestP)=>hn(requestP),t.__debug_n=(challenge,dx)=>pn(dx),t.__debug_wrap=kn",
  },
];

// ========== Base64 工具 ==========

function bytesToBase64(bytes) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++] || 0;
    const b1 = bytes[i++] || 0;
    const b2 = bytes[i++] || 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += chars[(n >> 18) & 63];
    out += chars[(n >> 12) & 63];
    out += i - 2 < bytes.length ? chars[(n >> 6) & 63] : "=";
    out += i - 1 < bytes.length ? chars[n & 63] : "=";
  }
  return out;
}

function base64ToBytes(base64) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const clean = String(base64 || "").replace(/[^A-Za-z0-9+/=]/g, "");
  const bytes = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = chars.indexOf(clean[i]);
    const c1 = chars.indexOf(clean[i + 1]);
    const c2 = chars.indexOf(clean[i + 2]);
    const c3 = chars.indexOf(clean[i + 3]);
    const n = ((c0 & 63) << 18) | ((c1 & 63) << 12) | (((c2 < 0 ? 0 : c2) & 63) << 6) | ((c3 < 0 ? 0 : c3) & 63);
    bytes.push((n >> 16) & 255);
    if (clean[i + 2] !== "=") bytes.push((n >> 8) & 255);
    if (clean[i + 3] !== "=") bytes.push(n & 255);
  }
  return bytes;
}

function isEncodedSolverFailure(value) {
  try {
    const decoded = String.fromCharCode(...base64ToBytes(value));
    return /^\d+:\s*[A-Za-z]*Error\b/.test(decoded);
  } catch (_) {
    return false;
  }
}

function isSessionObserverFailure(value) {
  if (isEncodedSolverFailure(value)) return true;
  try {
    const wrapped = JSON.parse(value);
    return isEncodedSolverFailure(wrapped && wrapped.so);
  } catch (_) {
    return false;
  }
}

// ========== localStorage / sessionStorage ==========

function createStorage(initialKeys = []) {
  const map = new Map();
  const storage = {};
  Object.defineProperties(storage, {
    length: { get: () => map.size, enumerable: false },
    clear: {
      value() {
        for (const key of map.keys()) delete storage[key];
        map.clear();
      },
      enumerable: false,
    },
    getItem: {
      value(key) { return map.has(String(key)) ? map.get(String(key)) : null; },
      enumerable: false,
    },
    setItem: {
      value(key, value) {
        const normalizedKey = String(key);
        const normalizedValue = String(value);
        map.set(normalizedKey, normalizedValue);
        Object.defineProperty(storage, normalizedKey, {
          value: normalizedValue,
          writable: true,
          configurable: true,
          enumerable: true,
        });
      },
      enumerable: false,
    },
    removeItem: {
      value(key) {
        const normalizedKey = String(key);
        map.delete(normalizedKey);
        delete storage[normalizedKey];
      },
      enumerable: false,
    },
    key: {
      value(index) { return [...map.keys()][index] || null; },
      enumerable: false,
    },
  });
  for (const key of initialKeys) {
    if (String(key || "")) storage.setItem(key, "");
  }
  return storage;
}

// ========== 运行时 payload（模块级引用，供 createElement 等读取）==========
let _runtimePayload = {};
const _eventTargetListeners = new WeakMap();

function installEventTarget(target) {
  const listeners = new Map();
  _eventTargetListeners.set(target, listeners);
  target.addEventListener = function addEventListener(type, listener, options) {
    if (!listener || (typeof listener !== "function" && typeof listener.handleEvent !== "function")) return;
    const eventType = String(type || "");
    const entries = listeners.get(eventType) || [];
    if (entries.some(entry => entry.listener === listener)) return;
    entries.push({ listener, once: !!(options && typeof options === "object" && options.once) });
    listeners.set(eventType, entries);
  };
  target.removeEventListener = function removeEventListener(type, listener) {
    const eventType = String(type || "");
    const entries = listeners.get(eventType);
    if (!entries) return;
    listeners.set(eventType, entries.filter(entry => entry.listener !== listener));
  };
  target.dispatchEvent = function dispatchEvent(event) {
    if (!event || !event.type) throw new TypeError("event.type is required");
    if (event.target == null) {
      try { Object.defineProperty(event, "target", { value: target, configurable: true }); } catch (_) {}
    }
    try { Object.defineProperty(event, "currentTarget", { value: target, configurable: true }); } catch (_) {}
    const entries = [...(listeners.get(String(event.type)) || [])];
    for (const entry of entries) {
      try {
        if (typeof entry.listener === "function") entry.listener.call(target, event);
        else entry.listener.handleEvent.call(entry.listener, event);
      } catch (_) {}
      if (entry.once) target.removeEventListener(event.type, entry.listener);
    }
    const handler = target[`on${event.type}`];
    if (typeof handler === "function") {
      try { handler.call(target, event); } catch (_) {}
    }
    return !event.defaultPrevented;
  };
  return target;
}

function _createBehaviorEvent(type, init = {}) {
  return {
    type,
    bubbles: true,
    cancelable: true,
    composed: true,
    defaultPrevented: false,
    isTrusted: false,
    timeStamp: globalThis.performance && typeof globalThis.performance.now === "function"
      ? globalThis.performance.now()
      : _RealDate.now(),
    preventDefault() { if (this.cancelable) this.defaultPrevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
    composedPath() { return [globalThis.document && globalThis.document.body, globalThis.document, globalThis].filter(Boolean); },
    ...init,
  };
}

function _dispatchBehaviorEvent(type, init, sourceTarget) {
  const event = _createBehaviorEvent(type, init);
  const targets = [...new Set([
    sourceTarget || (globalThis.document && globalThis.document.body),
    globalThis.document,
    globalThis,
  ].filter(Boolean))];
  for (const target of targets) target.dispatchEvent(event);
  return event;
}

function _behaviorModifierFields() {
  return { ctrlKey: false, metaKey: false, altKey: false };
}

function _resolvePasteShortcut(runtimePayload = {}) {
  const isMac = Boolean(runtimePayload.is_mac)
    || /mac/i.test(String(runtimePayload.navigator_platform || runtimePayload.user_agent || ""));
  return {
    key: isMac ? "Meta" : "Control",
    code: isMac ? "MetaLeft" : "ControlLeft",
    keyCode: isMac ? 91 : 17,
    ctrlKey: !isMac,
    metaKey: isMac,
  };
}

function _resolveBehaviorSequence(flow, behaviorInput = {}) {
  const flowName = String(flow || "");
  if (flowName === "email_otp_validate") {
    return { pasteText: String(behaviorInput.otp || ""), keys: [] };
  }
  if (flowName === "oauth_create_account") {
    const name = String(behaviorInput.name || "");
    const age = String(behaviorInput.age || "");
    return {
      pasteText: "",
      keys: name && age ? [...name, "Tab", ...age] : [],
    };
  }
  return { pasteText: "", keys: [] };
}

async function simulateHumanBehavior(rawDurationMs, flow, behaviorInput = {}) {
  const parsedDuration = Number(rawDurationMs);
  const durationMs = Number.isFinite(parsedDuration) && parsedDuration > 0
    ? Math.floor(parsedDuration)
    : 0;
  if (!durationMs) return { durationMs: 0, eventCount: 0 };

  const width = Math.max(1, Number(globalThis.innerWidth || 1920));
  const height = Math.max(1, Number(globalThis.innerHeight || 1080));
  let x = Math.floor(width * (0.2 + Math.random() * 0.6));
  let y = Math.floor(height * (0.2 + Math.random() * 0.6));
  const flowName = String(flow || "");
  const isOtpFlow = flowName === "email_otp_validate";
  const isCreateAccountFlow = flowName === "oauth_create_account";
  const behaviorSequence = _resolveBehaviorSequence(flowName, behaviorInput);
  const inputElement = (isOtpFlow || isCreateAccountFlow) && globalThis.document
    ? globalThis.document.createElement("input")
    : null;
  if (inputElement) {
    inputElement.type = "text";
    inputElement.inputMode = isOtpFlow ? "numeric" : "text";
    inputElement.maxLength = isOtpFlow ? 6 : 128;
    inputElement.value = "";
    inputElement.clientWidth = Math.min(280, width);
    inputElement.clientHeight = Math.min(44, height);
    inputElement.getBoundingClientRect = () => {
      const targetWidth = inputElement.clientWidth;
      const targetHeight = inputElement.clientHeight;
      const left = Math.max(0, Math.min(width - targetWidth, x - targetWidth / 2));
      const top = Math.max(0, Math.min(height - targetHeight, y - targetHeight / 2));
      return {
        x: left,
        y: top,
        width: targetWidth,
        height: targetHeight,
        top,
        left,
        right: left + targetWidth,
        bottom: top + targetHeight,
      };
    };
    globalThis.document.body.appendChild(inputElement);
  }
  const otpInput = isOtpFlow ? inputElement : null;
  const createAccountInput = isCreateAccountFlow ? inputElement : null;
  let eventCount = 0;
  const dispatch = (type, init, sourceTarget) => {
    const event = _dispatchBehaviorEvent(type, init, sourceTarget);
    eventCount += 1;
    return event;
  };
  const pause = (minimumMs, maximumMs) => new Promise(resolve => {
    const span = Math.max(0, maximumMs - minimumMs);
    const delayMs = minimumMs + Math.floor(Math.random() * (span + 1));
    _realSetTimeout(resolve, delayMs);
  });
  const mouseFields = ({
    buttons = 0,
    button = -1,
    pressure = buttons ? 0.5 : 0,
    sourceTarget = null,
  } = {}) => {
    const target = sourceTarget || (globalThis.document && globalThis.document.body);
    const rect = target && typeof target.getBoundingClientRect === "function"
      ? target.getBoundingClientRect()
      : { left: 0, top: 0 };
    return {
      view: globalThis,
      detail: 0,
      screenX: Number(globalThis.screenX || 0) + x,
      screenY: Number(globalThis.screenY || 0) + y,
      clientX: x,
      clientY: y,
      pageX: x + Number(globalThis.scrollX || 0),
      pageY: y + Number(globalThis.scrollY || 0),
      offsetX: x - Number(rect.left || 0),
      offsetY: y - Number(rect.top || 0),
      movementX: 0,
      movementY: 0,
      button,
      buttons,
      relatedTarget: null,
      pointerId: 1,
      width: 1,
      height: 1,
      pressure,
      tangentialPressure: 0,
      tiltX: 0,
      tiltY: 0,
      twist: 0,
      pointerType: "mouse",
      isPrimary: true,
      ..._behaviorModifierFields(),
    };
  };
  const moveMouse = () => {
    const previousX = x;
    const previousY = y;
    let deltaX = Math.floor(Math.random() * 65) - 32;
    let deltaY = Math.floor(Math.random() * 49) - 24;
    if (deltaX === 0 && deltaY === 0) deltaX = 1;
    x = Math.max(0, Math.min(width - 1, x + deltaX));
    y = Math.max(0, Math.min(height - 1, y + deltaY));
    if (x === previousX && y === previousY) {
      x = Math.max(0, Math.min(width - 1, x + (x > width / 2 ? -1 : 1)));
    }
    const fields = { ...mouseFields(), movementX: x - previousX, movementY: y - previousY };
    dispatch("pointermove", fields);
    dispatch("mousemove", fields);
  };
  const clickMouse = async (sourceTarget) => {
    const downFields = mouseFields({ buttons: 1, button: 0, pressure: 0.5, sourceTarget });
    dispatch("pointerdown", downFields, sourceTarget);
    dispatch("mousedown", downFields, sourceTarget);
    if (sourceTarget && globalThis.document) globalThis.document.activeElement = sourceTarget;
    await pause(28, 68);
    const upFields = mouseFields({ buttons: 0, button: 0, pressure: 0, sourceTarget });
    dispatch("pointerup", upFields, sourceTarget);
    dispatch("mouseup", upFields, sourceTarget);
    dispatch("click", { ...upFields, detail: 1 }, sourceTarget);
  };
  const scrollPage = () => {
    const root = globalThis.document && globalThis.document.documentElement;
    const body = globalThis.document && globalThis.document.body;
    const viewportHeight = Math.max(1, Number(globalThis.innerHeight || 0));
    const scrollHeight = Math.max(
      Number(root && root.scrollHeight || 0),
      Number(body && body.scrollHeight || 0),
    );
    const maxScrollY = Math.max(0, scrollHeight - viewportHeight);
    if (!maxScrollY) return;
    const currentY = Math.max(0, Math.min(maxScrollY, Number(globalThis.scrollY || 0)));
    const magnitude = 48 + Math.floor(Math.random() * 153);
    const direction = currentY <= 0 ? 1 : (currentY >= maxScrollY ? -1 : (Math.random() < 0.25 ? -1 : 1));
    const deltaY = direction * magnitude;
    const nextY = Math.max(0, Math.min(maxScrollY, currentY + deltaY));
    dispatch("wheel", { ...mouseFields({ button: 0 }), deltaX: 0, deltaY, deltaZ: 0, deltaMode: 0 });
    if (nextY === currentY) return;
    globalThis.scrollY = nextY;
    globalThis.pageYOffset = nextY;
    if (root) root.scrollTop = nextY;
    if (body) body.scrollTop = nextY;
    dispatch("scroll", { cancelable: false });
  };
  const pressKey = async () => {
    const key = "Escape";
    const code = "Escape";
    const keyCode = 27;
    const fields = {
      key,
      code,
      location: 0,
      ctrlKey: false,
      shiftKey: false,
      altKey: false,
      metaKey: false,
      repeat: false,
      isComposing: false,
      charCode: 0,
      keyCode,
      which: keyCode,
    };
    dispatch("keydown", fields);
    await pause(24, 64);
    dispatch("keyup", fields);
  };
  const pasteOtp = async () => {
    const pastedText = behaviorSequence.pasteText;
    if (!otpInput || !globalThis.document || !pastedText) return;
    globalThis.document.activeElement = otpInput;
    const pasteShortcut = _resolvePasteShortcut(_runtimePayload);
    const controlDown = {
      key: pasteShortcut.key,
      code: pasteShortcut.code,
      location: 1,
      ctrlKey: pasteShortcut.ctrlKey,
      shiftKey: false,
      altKey: false,
      metaKey: pasteShortcut.metaKey,
      repeat: false,
      isComposing: false,
      charCode: 0,
      keyCode: pasteShortcut.keyCode,
      which: pasteShortcut.keyCode,
    };
    const pasteKey = {
      ...controlDown,
      key: "v",
      code: "KeyV",
      location: 0,
      keyCode: 86,
      which: 86,
    };
    dispatch("keydown", controlDown, otpInput);
    await pause(18, 38);
    dispatch("keydown", pasteKey, otpInput);
    await pause(8, 20);
    const clipboardData = {
      types: ["text/plain"],
      items: [],
      files: [],
      getData(type) { return type === "text" || type === "text/plain" ? pastedText : ""; },
    };
    const pasteEvent = dispatch("paste", { clipboardData }, otpInput);
    if (!pasteEvent.defaultPrevented) {
      const beforeInput = dispatch("beforeinput", {
        data: pastedText,
        inputType: "insertFromPaste",
        isComposing: false,
      }, otpInput);
      if (!beforeInput.defaultPrevented) {
        otpInput.value = pastedText;
        dispatch("input", {
          data: pastedText,
          inputType: "insertFromPaste",
          isComposing: false,
          cancelable: false,
        }, otpInput);
      }
    }
    await pause(18, 42);
    dispatch("keyup", pasteKey, otpInput);
    dispatch("keyup", { ...controlDown, ctrlKey: false, metaKey: false }, otpInput);
  };
  const typeCreateAccountInput = async () => {
    if (!createAccountInput || !globalThis.document) return;
    globalThis.document.activeElement = createAccountInput;
    const keys = behaviorSequence.keys;
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      const isTab = key === "Tab";
      const isDigit = key >= "0" && key <= "9";
      const isLetter = /^[a-z]$/i.test(key);
      const code = isTab ? "Tab" : (isDigit ? `Digit${key}` : (isLetter ? `Key${key.toUpperCase()}` : "Space"));
      const keyCode = isTab ? 9 : (key === " " ? 32 : (isDigit ? key : key.toUpperCase()).charCodeAt(0));
      const fields = {
        key,
        code,
        location: 0,
        ctrlKey: false,
        shiftKey: isLetter && key === key.toUpperCase(),
        altKey: false,
        metaKey: false,
        repeat: false,
        isComposing: false,
        charCode: 0,
        keyCode,
        which: keyCode,
      };
      dispatch("keydown", fields, createAccountInput);
      if (!isTab) {
        const beforeInput = dispatch("beforeinput", {
          data: key,
          inputType: "insertText",
          isComposing: false,
        }, createAccountInput);
        if (!beforeInput.defaultPrevented) {
          createAccountInput.value += key;
          dispatch("input", {
            data: key,
            inputType: "insertText",
            isComposing: false,
            cancelable: false,
          }, createAccountInput);
        }
      } else {
        createAccountInput.value = "";
      }
      await pause(16, 30);
      dispatch("keyup", fields, createAccountInput);
      if (index + 1 < keys.length) await pause(28, 58);
    }
  };

  const startedAt = _RealDate.now();
  const deadline = startedAt + durationMs;
  const waitForAction = async () => {
    const remaining = deadline - _RealDate.now();
    if (remaining <= 0) return false;
    const delayMs = Math.min(remaining, 28 + Math.floor(Math.random() * 49));
    await new Promise(resolve => _realSetTimeout(resolve, delayMs));
    return _RealDate.now() < deadline;
  };
  const clickPrimaryTarget = () => clickMouse(inputElement || (globalThis.document && globalThis.document.body));
  const runScheduledActions = async (actionsToRun) => {
    for (const action of actionsToRun) {
      if (!await waitForAction()) return false;
      await action();
    }
    return true;
  };
  const preInputActions = isOtpFlow
    ? [moveMouse, moveMouse, clickPrimaryTarget]
    : [moveMouse, moveMouse, moveMouse, clickPrimaryTarget];
  await runScheduledActions(preInputActions);
  if (isOtpFlow) {
    if (_RealDate.now() < deadline) await waitForAction();
    await pasteOtp();
  } else if (isCreateAccountFlow) {
    if (_RealDate.now() < deadline) await waitForAction();
    await typeCreateAccountInput();
  }
  const remainingInitialActions = isOtpFlow || isCreateAccountFlow
    ? [moveMouse, scrollPage]
    : [scrollPage, pressKey];
  for (const action of remainingInitialActions) {
    if (!await waitForAction()) break;
    await action();
  }
  const actions = [moveMouse, moveMouse, moveMouse, scrollPage, clickPrimaryTarget];
  while (await waitForAction()) {
    await actions[Math.floor(Math.random() * actions.length)]();
  }
  return { durationMs: Math.max(0, _RealDate.now() - startedAt), eventCount };
}

const FLOW_HOST_PAGE_URLS = {
  authorize_continue: "https://auth.openai.com/create-account",
  username_password_create: "https://auth.openai.com/create-account/password",
  password_verify: "https://auth.openai.com/log-in/password",
  email_otp_validate: "https://auth.openai.com/email-verification",
  oauth_create_account: "https://auth.openai.com/about-you",
  chat_requirements: "https://chatgpt.com/",
  update_organization: "https://platform.openai.com/welcome?step=create",
};

const AUTH_SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260810913b/sdk.js";
const CHATGPT_SENTINEL_BUILD = "prod-fb4a8a2a751dfec391053cfd7b01c52699ccf78c";
const AUTH_SCRIPT_URLS = [
  AUTH_SENTINEL_SDK_URL,
];
const AUTH_ROUTE_NAMES = new Set([
  "default",
  "authorize_continue",
  "username_password_create",
  "password_verify",
  "email_otp_validate",
  "oauth_create_account",
  "log_in",
]);

const CHROME_NAVIGATOR_PROTO_OWN_KEYS = [
  "vendorSub", "productSub", "vendor", "maxTouchPoints", "scheduling",
  "userActivation", "geolocation", "doNotTrack", "webkitTemporaryStorage",
  "webkitPersistentStorage", "hardwareConcurrency", "cookieEnabled",
  "appCodeName", "appName", "appVersion", "platform", "product",
  "userAgent", "language", "languages", "onLine", "webdriver", "plugins",
  "mimeTypes", "pdfViewerEnabled", "connection", "getGamepads",
  "javaEnabled", "sendBeacon", "vibrate", "windowControlsOverlay",
  "deprecatedRunAdAuctionEnforcesKAnonymity", "protectedAudience",
  "clipboard", "credentials", "keyboard", "managed", "mediaDevices",
  "serviceWorker", "virtualKeyboard", "wakeLock", "deviceMemory",
  "userAgentData", "locks", "storage", "gpu", "login", "ink",
  "mediaCapabilities", "devicePosture", "hid", "mediaSession",
  "permissions", "presentation", "serial", "usb", "xr", "storageBuckets",
  "adAuctionComponents", "runAdAuction", "canLoadAdAuctionFencedFrame",
  "clearAppBadge", "getBattery", "getUserMedia", "requestMIDIAccess",
  "requestMediaKeySystemAccess", "setAppBadge", "webkitGetUserMedia",
  "clearOriginJoinedAdInterestGroups", "createAuctionNonce",
  "joinAdInterestGroup", "leaveAdInterestGroup", "updateAdInterestGroups",
  "deprecatedReplaceInURN", "deprecatedURNToURL",
  "getInstalledRelatedApps", "getInterestGroupAdAuctionData",
  "registerProtocolHandler", "unregisterProtocolHandler",
];

const SAFARI_NAVIGATOR_PROTO_OWN_KEYS = [
  "vendorSub", "productSub", "vendor", "maxTouchPoints", "userActivation",
  "geolocation", "doNotTrack", "plugins", "mimeTypes", "pdfViewerEnabled",
  "hardwareConcurrency", "cookieEnabled", "appCodeName", "appName",
  "appVersion", "platform", "product", "userAgent", "language", "languages",
  "onLine", "webdriver", "getGamepads", "javaEnabled", "sendBeacon", "clipboard",
  "credentials", "mediaDevices", "serviceWorker", "permissions",
  "storage", "mediaSession", "mediaCapabilities",
];

const SAFARI_ALWAYS_UNSUPPORTED_NAVIGATOR_KEYS = new Set([
  "deviceMemory", "userAgentData", "gpu", "serial", "hid", "usb",
  "bluetooth", "managed", "login", "ink", "virtualKeyboard",
  "windowControlsOverlay", "devicePosture", "xr", "storageBuckets",
  "protectedAudience", "deprecatedRunAdAuctionEnforcesKAnonymity",
  "adAuctionComponents", "runAdAuction", "canLoadAdAuctionFencedFrame",
  "clearOriginJoinedAdInterestGroups", "createAuctionNonce",
  "joinAdInterestGroup", "leaveAdInterestGroup", "updateAdInterestGroups",
  "deprecatedReplaceInURN", "deprecatedURNToURL",
  "getInterestGroupAdAuctionData",
  "scheduling", "connection", "webkitTemporaryStorage", "webkitPersistentStorage",
  "vibrate", "getBattery", "keyboard", "presentation",
]);

const LOG_IN_WINDOW_OWN_KEYS = [
  "__reactRouterContext", "$RB", "$RV", "$RC", "$RT",
  "__reactRouterManifest", "__STATSIG__", "__reactRouterVersion",
  "__REACT_INTL_CONTEXT__", "__SEGMENT_INSPECTOR__",
  "__reactRouterRouteModules", "__reactRouterDataRouter",
  "__sentinel_token_pending", "__sentinel_init_pending",
  "__oai_so_h", "__oai_so_hi", "__oai_so_hp", "__oai_so_hw",
  "__oai_so_s", "__oai_so_k", "__oai_so_kp", "__oai_so_we",
  "__oai_so_wb", "__oai_so_wl", "__oai_so_t0", "__oai_so_p",
  "__oai_so_pc", "__oai_so_m", "__oai_so_i", "__oai_so_ht",
  "__oai_so_hc", "__oai_so_ss", "__oai_so_ss2", "__oai_so_sn",
  "__oai_so_cs", "__oai_so_cs2", "__oai_so_cn", "__oai_so_st",
  "__oai_so_sw", "__oai_so_sp", "__oai_so_spt", "__oai_so_sx0",
  "__oai_so_sy0", "__oai_so_lx", "__oai_so_ly", "DD_RUM",
  "SentinelSDK",
];

const ROUTE_PROFILES = {
  default: {
    name: "default",
    hostPageUrl: FLOW_HOST_PAGE_URLS.authorize_continue,
    documentKeyKinds: ["reactListening"],
    windowOwnKeys: ["__oai_so_hc"],
    navigatorProtoOwnKeys: CHROME_NAVIGATOR_PROTO_OWN_KEYS,
    keepDocumentLocationEnumerable: false,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  authorize_continue: {
    name: "authorize_continue",
    hostPageUrl: FLOW_HOST_PAGE_URLS.authorize_continue,
    documentKeyKinds: ["reactContainer", "location"],
    windowOwnKeys: ["onclose", "onauxclick"],
    navigatorProtoOwnKeys: ["clipboard", "mimeTypes"],
    keepDocumentLocationEnumerable: true,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  username_password_create: {
    name: "username_password_create",
    hostPageUrl: FLOW_HOST_PAGE_URLS.username_password_create,
    documentKeyKinds: ["reactContainer", "location"],
    windowOwnKeys: ["pageXOffset", "status"],
    navigatorProtoOwnKeys: ["clipboard", "usb"],
    keepDocumentLocationEnumerable: true,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  password_verify: {
    name: "password_verify",
    hostPageUrl: FLOW_HOST_PAGE_URLS.password_verify,
    documentKeyKinds: ["location", "reactContainer", "reactListening"],
    windowOwnKeys: LOG_IN_WINDOW_OWN_KEYS,
    navigatorProtoOwnKeys: CHROME_NAVIGATOR_PROTO_OWN_KEYS,
    keepDocumentLocationEnumerable: true,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  email_otp_validate: {
    name: "email_otp_validate",
    hostPageUrl: FLOW_HOST_PAGE_URLS.email_otp_validate,
    documentKeyKinds: ["reactListening"],
    windowOwnKeys: ["__oai_so_hc"],
    navigatorProtoOwnKeys: ["userAgent"],
    keepDocumentLocationEnumerable: false,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  oauth_create_account: {
    name: "oauth_create_account",
    hostPageUrl: FLOW_HOST_PAGE_URLS.oauth_create_account,
    documentKeyKinds: ["reactContainer", "location"],
    windowOwnKeys: ["onclose", "onauxclick"],
    navigatorProtoOwnKeys: ["clipboard", "mimeTypes"],
    keepDocumentLocationEnumerable: true,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  chat_requirements: {
    name: "chat_requirements",
    hostPageUrl: FLOW_HOST_PAGE_URLS.chat_requirements,
    documentKeyKinds: ["reactListening"],
    windowOwnKeys: ["CryptoJS"],
    navigatorProtoOwnKeys: ["clearOriginJoinedAdInterestGroups"],
    keepDocumentLocationEnumerable: false,
    scriptUrls: [],
    sdkBuild: CHATGPT_SENTINEL_BUILD,
  },
  log_in: {
    name: "log_in",
    hostPageUrl: "https://auth.openai.com/log-in",
    documentKeyKinds: ["location", "reactContainer", "reactListening"],
    windowOwnKeys: LOG_IN_WINDOW_OWN_KEYS,
    navigatorProtoOwnKeys: CHROME_NAVIGATOR_PROTO_OWN_KEYS,
    keepDocumentLocationEnumerable: true,
    scriptUrls: AUTH_SCRIPT_URLS,
  },
  update_organization: {
    name: "update_organization",
    hostPageUrl: FLOW_HOST_PAGE_URLS.update_organization,
    documentKeyKinds: ["privateStripeMetricsController", "location"],
    windowOwnKeys: ["window", "isSecureContext", "frameElement"],
    navigatorProtoOwnKeys: ["leaveAdInterestGroup", "mimeTypes", "webkitPersistentStorage"],
    keepDocumentLocationEnumerable: true,
    scriptUrls: [
      "https://js.stripe.com/v3",
      "https://platform.openai.com/sentinel/2d1db0d5/sdk.js",
      "https://cdn.platform.openai.com/deployments/chatkit/chatkit.js",
    ],
  },
};

function _cloneJsonValue(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function _hashString(text) {
  let hash = 2166136261;
  const value = String(text || "");
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function _mixSeed(...parts) {
  return _hashString(parts.map((part) => String(part ?? "")).join("|")) >>> 0;
}

function _makePrng(seed) {
  let state = (Number(seed) >>> 0) || 0x6d2b79f5;
  return {
    next() {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state / 0x100000000;
    },
    getState() {
      return state >>> 0;
    },
    setState(nextSeed) {
      state = (Number(nextSeed) >>> 0) || 0x6d2b79f5;
    },
  };
}

function _buildSuffix(prng, minLength = 10, maxLength = 14) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const length = minLength + Math.floor(prng.next() * (maxLength - minLength + 1));
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += chars[Math.floor(prng.next() * chars.length)];
  }
  return out;
}

function _resolveHostPageUrl(payload) {
  const hostPageUrl = String(payload.host_page_url || "").trim();
  if (hostPageUrl) return hostPageUrl;
  const flow = String(payload.flow || payload.action || "").trim();
  return FLOW_HOST_PAGE_URLS[flow] || FLOW_HOST_PAGE_URLS.authorize_continue;
}

function _detectBrowserProfile(payload) {
  const explicitProfile = String(payload.browser_profile || payload.browser_family || "").trim().toLowerCase();
  if (explicitProfile === "safari") return "safari";
  if (explicitProfile === "chrome" || explicitProfile === "chromium") return "chrome";
  const userAgent = String(payload.user_agent || "");
  const isSafari = /Safari\//i.test(userAgent)
    && !/(?:Chrome|Chromium|CriOS|Edg|EdgiOS|EdgA|OPR|Opera|Electron)\//i.test(userAgent);
  return isSafari ? "safari" : "chrome";
}

function _safariVersion(payload) {
  const match = String(payload.user_agent || "").match(/Version\/(\d+)(?:\.(\d+))?/i);
  return match ? [Number(match[1]), Number(match[2] || 0)] : [18, 0];
}

function _versionBefore(version, major, minor) {
  return version[0] < major || (version[0] === major && version[1] < minor);
}

function _safariUnsupportedNavigatorKeys(payload) {
  const keys = new Set(SAFARI_ALWAYS_UNSUPPORTED_NAVIGATOR_KEYS);
  const version = _safariVersion(payload);
  if (_versionBefore(version, 15, 4)) keys.add("locks");
  if (_versionBefore(version, 16, 4)) {
    keys.add("wakeLock");
    keys.add("userActivation");
  }
  return keys;
}

function _resolveRouteProfile(payload) {
  const hostPageUrl = _resolveHostPageUrl(payload);
  const path = (() => {
    try {
      return new URL(hostPageUrl).pathname;
    } catch (_) {
      return "";
    }
  })();
  const flow = String(payload.flow || payload.action || "").trim();
  let profile;
  if (path === "/log-in") profile = ROUTE_PROFILES.log_in;
  else if (path === "/log-in/password") profile = ROUTE_PROFILES.password_verify;
  else profile = ROUTE_PROFILES[flow] || ROUTE_PROFILES.default;
  const browserProfile = _detectBrowserProfile(payload);
  const resolved = { ...profile, hostPageUrl, browserProfile };
  if (browserProfile !== "safari") return resolved;
  const unsupportedKeys = _safariUnsupportedNavigatorKeys(payload);
  if (profile.navigatorProtoOwnKeys === CHROME_NAVIGATOR_PROTO_OWN_KEYS) {
    resolved.navigatorProtoOwnKeys = SAFARI_NAVIGATOR_PROTO_OWN_KEYS;
  } else {
    resolved.navigatorProtoOwnKeys = (resolved.navigatorProtoOwnKeys || [])
      .filter(key => !unsupportedKeys.has(key));
  }
  if (profile.name === "oauth_create_account") {
    resolved.documentKeyKinds = ["reactListening"];
    resolved.windowOwnKeys = ["onhashchange"];
  }
  if (profile.name === "chat_requirements" && browserProfile === "safari") {
    resolved.navigatorProtoOwnKeys = ["vendor"];
  }
  resolved.navigatorProtoOwnKeys = resolved.navigatorProtoOwnKeys
    .filter(key => !unsupportedKeys.has(key));
  return resolved;
}

function _createRuntimeState(payload, routeProfile) {
  const previous = payload.runtime_state && typeof payload.runtime_state === "object"
    ? payload.runtime_state
    : {};
  const localStorageKeys = Array.isArray(previous.local_storage_keys)
    ? previous.local_storage_keys
    : (Array.isArray(payload.local_storage_keys) ? payload.local_storage_keys : []);
  const seedBase = previous.seed_base != null
    ? (Number(previous.seed_base) >>> 0)
    : _mixSeed(
      payload.fingerprint_seed || "",
      payload.device_id || "",
      payload.flow || payload.action || "",
      routeProfile.hostPageUrl,
      payload.user_agent || "",
      payload.time_origin || "",
      payload.performance_now || "",
    );
  const prng = _makePrng(
    previous.rng_state != null
      ? previous.rng_state
      : seedBase
  );
  const perfNow = Number(previous.perf_now != null ? previous.perf_now : (payload.performance_now || 12345.67));
  const timeOrigin = Number(payload.time_origin || 1710000000000);
  const heapLimit = Number(payload.js_heap_size_limit || 4294705152);
  const heapTotal = Number(
    previous.heap_total_js != null
      ? previous.heap_total_js
      : Math.floor(heapLimit * (0.15 + prng.next() * 0.01))
  );
  const heapUsed = Number(
    previous.heap_used_js != null
      ? previous.heap_used_js
      : Math.floor(heapLimit * (0.08 + prng.next() * 0.005))
  );
  return {
    seed_base: seedBase,
    prng,
    perf_now: perfNow,
    time_origin: timeOrigin,
    wall_time_ms: Number(previous.wall_time_ms != null ? previous.wall_time_ms : Math.round(timeOrigin + perfNow)),
    heap_total_js: heapTotal,
    heap_used_js: heapUsed,
    history_state: previous.history_state && typeof previous.history_state === "object"
      ? _cloneJsonValue(previous.history_state)
      : null,
    react_document_keys: Array.isArray(previous.react_document_keys) && previous.react_document_keys.length
      ? previous.react_document_keys.slice()
      : null,
    navigator_proto_own_keys: Array.isArray(previous.navigator_proto_own_keys) && previous.navigator_proto_own_keys.length
      ? previous.navigator_proto_own_keys.slice()
      : (routeProfile.navigatorProtoOwnKeys || CHROME_NAVIGATOR_PROTO_OWN_KEYS).slice(),
    local_storage_keys: [...new Set(localStorageKeys.map(key => String(key || "")).filter(Boolean))],
    route_profile_name: String(previous.route_profile_name || routeProfile.name || "default"),
    browser_profile: String(previous.browser_profile || routeProfile.browserProfile || "chrome"),
  };
}

function _createDocumentOwnKeys(routeProfile, runtimeState) {
  if (Array.isArray(runtimeState.react_document_keys) && runtimeState.react_document_keys.length) {
    return runtimeState.react_document_keys.slice();
  }
  const keys = [];
  for (const kind of routeProfile.documentKeyKinds || []) {
    if (kind === "location") {
      keys.push("location");
    } else if (kind === "reactContainer") {
      keys.push(`__reactContainer$${_buildSuffix(runtimeState.prng)}`);
    } else if (kind === "reactListening") {
      keys.push(`_reactListening${_buildSuffix(runtimeState.prng)}`);
    } else if (kind === "reactEvents") {
      keys.push(`__reactEvents$${_buildSuffix(runtimeState.prng)}`);
    } else if (kind === "reactResources") {
      keys.push(`__reactResources$${_buildSuffix(runtimeState.prng)}`);
    } else if (kind === "privateStripeMetricsController") {
      keys.push("__privateStripeMetricsController2000");
    }
  }
  runtimeState.react_document_keys = keys.slice();
  return keys;
}

function _buildOrderedObject(keys, source, fallbackFactory) {
  const target = {};
  const seen = new Set();
  const addKey = (key, enumerable) => {
    if (!key || seen.has(key)) return;
    seen.add(key);
    const value = Object.prototype.hasOwnProperty.call(source, key)
      ? source[key]
      : (typeof fallbackFactory === "function" ? fallbackFactory(key) : undefined);
    Object.defineProperty(target, key, {
      value,
      writable: true,
      configurable: true,
      enumerable,
    });
  };
  for (const key of keys || []) addKey(key, true);
  for (const key of Object.keys(source || {})) addKey(key, false);
  return target;
}

function _makeNavigatorFallbackValue(key, payload) {
  switch (key) {
    case "adAuctionComponents":
      return [];
    case "leaveAdInterestGroup":
      {
        const method = function leaveAdInterestGroup() {
          return Promise.reject(new Error("NotSupportedError"));
        };
        Object.defineProperty(method, "toString", {
          value: () => "function leaveAdInterestGroup() { [native code] }",
        });
        return method;
      }
    case "runAdAuction":
    case "joinAdInterestGroup":
    case "updateAdInterestGroups":
    case "deprecatedReplaceInURN":
    case "deprecatedURNToURL":
    case "requestMIDIAccess":
    case "requestMediaKeySystemAccess":
    case "getInstalledRelatedApps":
    case "getInterestGroupAdAuctionData":
    case "registerProtocolHandler":
    case "unregisterProtocolHandler":
    case "createAuctionNonce":
    case "getUserMedia":
    case "webkitGetUserMedia":
      return function unsupportedNavigatorMethod() {
        return Promise.reject(new Error("NotSupportedError"));
      };
    case "clearOriginJoinedAdInterestGroups":
      {
        const method = function clearOriginJoinedAdInterestGroups() {
          return Promise.resolve();
        };
        Object.defineProperty(method, "toString", {
          value: () => "function clearOriginJoinedAdInterestGroups() { [native code] }",
        });
        return method;
      }
    case "canLoadAdAuctionFencedFrame":
      return function canLoadAdAuctionFencedFrame() {
        return false;
      };
    case "clearAppBadge":
      return function clearAppBadge() {
        return Promise.resolve();
      };
    case "setAppBadge":
      return function setAppBadge() {
        return Promise.resolve();
      };
    case "managed":
      return { [Symbol.toStringTag]: "NavigatorManagedData" };
    default:
      return payload[key];
  }
}

function _makeWindowPlaceholder(key, payload, context) {
  if (key === "__reactRouterContext" || key === "__reactRouterManifest" || key === "__reactRouterRouteModules" || key === "__reactRouterDataRouter") return {};
  if (key === "__reactRouterVersion") return "7";
  if (key === "__REACT_INTL_CONTEXT__" || key === "__SEGMENT_INSPECTOR__" || key === "__STATSIG__") return {};
  if (key === "__sentinel_token_pending" || key === "__sentinel_init_pending") return [];
  if (key === "$RB" || key === "$RV" || key === "$RC" || key === "$RT") return function reactBootstrapStub() {};
  if (key === "DD_RUM") return {};
  if (key === "frameElement") return null;
  if (key === "status") return "";
  if (key.startsWith("on")) return null;
  if (key === "__oai_so_hc") return context.hwConcurrency;
  if (key === "__oai_so_h") return context.screenH;
  if (key === "__oai_so_hw") return context.screenW;
  if (key === "__oai_so_hi") return context.innerH;
  if (key === "__oai_so_hp") return payload.host_page_url || context.hostPageUrl;
  if (key === "__oai_so_p") return payload.navigator_platform || "Win32";
  if (key === "__oai_so_pc") return 0;
  if (key === "__oai_so_s") return `${context.screenW}x${context.screenH}`;
  if (key === "__oai_so_m") return false;
  if (key === "__oai_so_i") return payload.device_id || "";
  if (key === "__oai_so_ht") return context.hostPageUrl;
  if (key === "__oai_so_lx" || key === "__oai_so_ly" || key === "__oai_so_sx0" || key === "__oai_so_sy0") return 0;
  if (key.startsWith("__oai_so_")) return 0;
  return {};
}

function _setEnumerable(target, key, enumerable) {
  if (!(key in target)) return;
  const desc = Object.getOwnPropertyDescriptor(target, key);
  if (!desc || !desc.configurable || desc.enumerable === enumerable) return;
  Object.defineProperty(target, key, { ...desc, enumerable });
}

function _seededPrng(label, extra = "") {
  return _makePrng(
    _mixSeed(
      _runtimePayload.fingerprint_seed || "",
      _runtimePayload.device_id || "",
      _runtimePayload.host_page_url || "",
      label,
      extra,
    )
  );
}

function _fillSeededByteArray(arr, label) {
  const prng = _seededPrng(label, arr.length);
  for (let i = 0; i < arr.length; i += 1) {
    arr[i] = Math.floor(prng.next() * 256);
  }
  return arr;
}

function _seededCanvasDataUrl(label) {
  const bytes = new Uint8Array(48);
  _fillSeededByteArray(bytes, label);
  return "data:image/png;base64," + bytesToBase64(bytes);
}

// ========== WebGL 扩展列表 ==========

const WEBGL1_EXTENSIONS = [
  "ANGLE_instanced_arrays", "EXT_blend_minmax", "EXT_color_buffer_half_float",
  "EXT_disjoint_timer_query", "EXT_float_blend", "EXT_frag_depth",
  "EXT_shader_texture_lod", "EXT_texture_compression_bptc",
  "EXT_texture_compression_rgtc", "EXT_texture_filter_anisotropic",
  "EXT_sRGB", "KHR_parallel_shader_compile", "OES_element_index_uint",
  "OES_fbo_render_mipmap", "OES_standard_derivatives", "OES_texture_float",
  "OES_texture_float_linear", "OES_texture_half_float",
  "OES_texture_half_float_linear", "OES_vertex_array_object",
  "WEBGL_color_buffer_float", "WEBGL_compressed_texture_s3tc",
  "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info",
  "WEBGL_debug_shaders", "WEBGL_depth_texture", "WEBGL_draw_buffers",
  "WEBGL_lose_context", "WEBGL_multi_draw",
];

const WEBGL2_EXTENSIONS = [
  "EXT_color_buffer_float", "EXT_color_buffer_half_float",
  "EXT_disjoint_timer_query_webgl2", "EXT_float_blend",
  "EXT_texture_compression_bptc", "EXT_texture_compression_rgtc",
  "EXT_texture_filter_anisotropic", "EXT_texture_norm16",
  "KHR_parallel_shader_compile", "OES_draw_buffers_indexed",
  "OES_texture_float_linear", "OVR_multiview2",
  "WEBGL_clip_cull_distance", "WEBGL_compressed_texture_s3tc",
  "WEBGL_compressed_texture_s3tc_srgb", "WEBGL_debug_renderer_info",
  "WEBGL_debug_shaders", "WEBGL_draw_instanced_base_vertex_base_instance",
  "WEBGL_lose_context", "WEBGL_multi_draw",
  "WEBGL_multi_draw_instanced_base_vertex_base_instance",
  "WEBGL_provoking_vertex",
];

// ========== WebGL Context Mock ==========

function _resolveGpuIdentity(payload) {
  const browserProfile = String(payload.browser_profile || _detectBrowserProfile(payload));
  if (browserProfile !== "safari") {
    return {
      vendor: String(payload.gpu_vendor || "Google Inc. (Intel)"),
      renderer: String(payload.gpu_renderer || "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    };
  }
  const requestedVendor = String(payload.gpu_vendor || "").trim();
  const requestedRenderer = String(payload.gpu_renderer || "").trim();
  return {
    vendor: /^Apple(?: Inc\.)?$/i.test(requestedVendor) ? requestedVendor : "Apple Inc.",
    renderer: /^Apple(?: GPU| M\d)/i.test(requestedRenderer)
      && !/(?:ANGLE|Direct3D|D3D)/i.test(requestedRenderer)
      ? requestedRenderer
      : "Apple GPU",
  };
}

function createWebGLContext(version, payload) {
  const browserProfile = String(payload.browser_profile || _detectBrowserProfile(payload));
  const { vendor: gpuVendor, renderer: gpuRenderer } = _resolveGpuIdentity(payload);
  const isWebGL2 = version === 2;
  const extensions = isWebGL2 ? WEBGL2_EXTENSIONS : WEBGL1_EXTENSIONS;

  const debugRendererInfo = {
    UNMASKED_VENDOR_WEBGL: 0x9245,
    UNMASKED_RENDERER_WEBGL: 0x9246,
  };

  // 根据 GPU 渲染器判断 max 值档次
  const isHighEnd = /RTX|RX 6|RX 7|M[2-9]|M\d+ Pro|M\d+ Max/i.test(gpuRenderer);
  const maxTexSize = isHighEnd ? 32768 : 16384;

  const ctx = {
    canvas: null,
    drawingBufferWidth: Number(payload.screen_width || 1920),
    drawingBufferHeight: Number(payload.screen_height || 1080),
    drawingBufferColorSpace: "srgb",

    getParameter(pname) {
      switch (pname) {
        case 0x1F00: return "WebKit";
        case 0x1F01: return "WebKit WebGL";
        case 0x1F02: return browserProfile === "safari"
          ? (isWebGL2 ? "WebGL 2.0" : "WebGL 1.0")
          : (isWebGL2
            ? "WebGL 2.0 (OpenGL ES 3.0 Chromium)"
            : "WebGL 1.0 (OpenGL ES 2.0 Chromium)");
        case 0x8B8C: return browserProfile === "safari"
          ? (isWebGL2 ? "WebGL GLSL ES 3.00" : "WebGL GLSL ES 1.0")
          : (isWebGL2
            ? "WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)"
            : "WebGL GLSL ES 1.0 (OpenGL ES GLSL ES 1.0 Chromium)");
        case 0x9245: return gpuVendor;
        case 0x9246: return gpuRenderer;
        case 0x0D33: return maxTexSize;
        case 0x851C: return maxTexSize;
        case 0x84E8: return maxTexSize;
        case 0x0D3A: return new Int32Array([32767, 32767]);
        case 0x8869: return 16;
        case 0x8DFB: return 4096;
        case 0x8DFC: return isWebGL2 ? 16 : 30;
        case 0x8B4D: return isWebGL2 ? 64 : 32;
        case 0x8B4C: return 16;
        case 0x8872: return 16;
        case 0x8DFD: return 1024;
        case 0x846E: return new Float32Array([1, 1]);
        case 0x846D: return new Float32Array([1, 1024]);
        case 0x0D56: return 24;
        case 0x0D57: return 8;
        case 0x0D52: return 8;
        case 0x0D53: return 8;
        case 0x0D54: return 8;
        case 0x0D55: return 8;
        case 0x0D50: return 4;
        case 0x8D57: return isHighEnd ? 16 : 8;
        case 0x0BA2: return 1;
        case 0x8038: return 4;
        case 0x80A9: return 4;
        case 0x80AA: return 4;
        case 0x821B: return isWebGL2 ? 16384 : undefined;
        case 0x822D: return isWebGL2 ? 2048 : undefined;
        case 0x822E: return isWebGL2 ? 2048 : undefined;
        case 0x8073: return isWebGL2 ? maxTexSize : undefined;
        case 0x88FF: return isWebGL2 ? 64 : undefined;
        case 0x8A2B: return isWebGL2 ? 12 : undefined;
        case 0x8A2D: return isWebGL2 ? 16 : undefined;
        default: return null;
      }
    },

    getExtension(name) {
      if (name === "WEBGL_debug_renderer_info") return debugRendererInfo;
      if (name === "WEBGL_lose_context") return { loseContext() {}, restoreContext() {} };
      if (name === "EXT_texture_filter_anisotropic") return { MAX_TEXTURE_MAX_ANISOTROPY_EXT: 0x84FF, TEXTURE_MAX_ANISOTROPY_EXT: 0x84FE };
      if (name === "WEBGL_draw_buffers") return { MAX_COLOR_ATTACHMENTS_WEBGL: 8, MAX_DRAW_BUFFERS_WEBGL: 8, drawBuffersWEBGL() {} };
      if (name === "ANGLE_instanced_arrays") return { drawArraysInstancedANGLE() {}, drawElementsInstancedANGLE() {}, vertexAttribDivisorANGLE() {} };
      if (name === "OES_vertex_array_object") return { createVertexArrayOES() { return {}; }, deleteVertexArrayOES() {}, isVertexArrayOES() { return false; }, bindVertexArrayOES() {} };
      if (name === "OES_standard_derivatives") return { FRAGMENT_SHADER_DERIVATIVE_HINT_OES: 0x8B8B };
      if (name === "WEBGL_debug_shaders") return { getTranslatedShaderSource() { return ""; } };
      if (extensions.includes(name)) return {};
      return null;
    },

    getSupportedExtensions() { return [...extensions]; },

    getShaderPrecisionFormat(_shaderType, _precisionType) {
      return { rangeMin: 127, rangeMax: 127, precision: 23 };
    },

    getContextAttributes() {
      return {
        alpha: true, antialias: true, depth: true, desynchronized: false,
        failIfMajorPerformanceCaveat: false, powerPreference: "default",
        premultipliedAlpha: true, preserveDrawingBuffer: false, stencil: false,
        xrCompatible: false,
      };
    },

    createShader() { return { _id: Math.random() }; },
    shaderSource() {},
    compileShader() {},
    getShaderParameter(_s, pname) { return pname === 0x8B81 ? true : 0; },
    getShaderInfoLog() { return ""; },
    createProgram() { return { _id: Math.random() }; },
    attachShader() {},
    linkProgram() {},
    getProgramParameter(_p, pname) { return pname === 0x8B82 ? true : 0; },
    getProgramInfoLog() { return ""; },
    useProgram() {},
    validateProgram() {},
    createBuffer() { return { _id: Math.random() }; },
    bindBuffer() {},
    bufferData() {},
    bufferSubData() {},
    createTexture() { return { _id: Math.random() }; },
    bindTexture() {},
    texParameteri() {},
    texParameterf() {},
    texImage2D() {},
    texSubImage2D() {},
    createFramebuffer() { return { _id: Math.random() }; },
    bindFramebuffer() {},
    framebufferTexture2D() {},
    framebufferRenderbuffer() {},
    checkFramebufferStatus() { return 0x8CD5; },
    createRenderbuffer() { return { _id: Math.random() }; },
    bindRenderbuffer() {},
    renderbufferStorage() {},
    viewport() {},
    clear() {},
    clearColor() {},
    clearDepth() {},
    clearStencil() {},
    colorMask() {},
    depthMask() {},
    stencilMask() {},
    enable() {},
    disable() {},
    isEnabled() { return false; },
    blendFunc() {},
    blendFuncSeparate() {},
    blendEquation() {},
    blendEquationSeparate() {},
    blendColor() {},
    depthFunc() {},
    depthRange() {},
    stencilFunc() {},
    stencilFuncSeparate() {},
    stencilOp() {},
    stencilOpSeparate() {},
    scissor() {},
    sampleCoverage() {},
    polygonOffset() {},
    cullFace() {},
    frontFace() {},
    lineWidth() {},
    hint() {},
    readPixels(_x, _y, _w, _h, _fmt, _type, pixels) {
      if (pixels && pixels.length) _fillSeededByteArray(pixels, `webgl-readpixels:${version}:${pixels.length}`);
    },
    getError() { return 0; },
    isContextLost() { return false; },
    flush() {},
    finish() {},
    deleteShader() {},
    deleteProgram() {},
    deleteBuffer() {},
    deleteTexture() {},
    deleteFramebuffer() {},
    deleteRenderbuffer() {},
    pixelStorei() {},
    activeTexture() {},
    generateMipmap() {},
    getAttribLocation() { return 0; },
    getUniformLocation() { return { _id: Math.random() }; },
    getActiveAttrib() { return { size: 1, type: 0x8B50, name: "a" }; },
    getActiveUniform() { return { size: 1, type: 0x8B50, name: "u" }; },
    enableVertexAttribArray() {},
    disableVertexAttribArray() {},
    vertexAttribPointer() {},
    vertexAttrib1f() {},
    vertexAttrib2f() {},
    vertexAttrib3f() {},
    vertexAttrib4f() {},
    drawArrays() {},
    drawElements() {},
    uniform1i() {},
    uniform1f() {},
    uniform2f() {},
    uniform2fv() {},
    uniform3f() {},
    uniform3fv() {},
    uniform4f() {},
    uniform4fv() {},
    uniform1iv() {},
    uniform1fv() {},
    uniformMatrix2fv() {},
    uniformMatrix3fv() {},
    uniformMatrix4fv() {},
    isShader() { return true; },
    isProgram() { return true; },
    isBuffer() { return true; },
    isTexture() { return true; },
    isFramebuffer() { return true; },
    isRenderbuffer() { return true; },
  };

  // WebGL 2 额外方法
  if (isWebGL2) {
    Object.assign(ctx, {
      createVertexArray() { return { _id: Math.random() }; },
      deleteVertexArray() {},
      bindVertexArray() {},
      isVertexArray() { return false; },
      drawArraysInstanced() {},
      drawElementsInstanced() {},
      vertexAttribDivisor() {},
      createSampler() { return { _id: Math.random() }; },
      deleteSampler() {},
      bindSampler() {},
      samplerParameteri() {},
      samplerParameterf() {},
      fenceSync() { return { _id: Math.random() }; },
      deleteSync() {},
      clientWaitSync() { return 0x911D; },
      waitSync() {},
      getSyncParameter() { return 0x9119; },
      createTransformFeedback() { return { _id: Math.random() }; },
      deleteTransformFeedback() {},
      bindTransformFeedback() {},
      beginTransformFeedback() {},
      endTransformFeedback() {},
      transformFeedbackVaryings() {},
      getTransformFeedbackVarying() { return { size: 1, type: 0x8B50, name: "v" }; },
      readBuffer() {},
      drawBuffers() {},
      blitFramebuffer() {},
      renderbufferStorageMultisample() {},
      texStorage2D() {},
      texStorage3D() {},
      texImage3D() {},
      texSubImage3D() {},
      compressedTexImage3D() {},
      compressedTexSubImage3D() {},
      copyTexSubImage3D() {},
      getBufferSubData() {},
      uniform1ui() {},
      uniform2ui() {},
      uniform3ui() {},
      uniform4ui() {},
      uniformMatrix2x3fv() {},
      uniformMatrix3x2fv() {},
      uniformMatrix2x4fv() {},
      uniformMatrix4x2fv() {},
      uniformMatrix3x4fv() {},
      uniformMatrix4x3fv() {},
      getUniformBlockIndex() { return 0; },
      uniformBlockBinding() {},
      createQuery() { return { _id: Math.random() }; },
      deleteQuery() {},
      beginQuery() {},
      endQuery() {},
      getQuery() { return null; },
      getQueryParameter() { return 0; },
    });
  }

  return ctx;
}

// ========== Canvas 2D Context Mock ==========

function createCanvas2DContext(canvas) {
  const ctx = {
    canvas,
    fillStyle: "#000000",
    strokeStyle: "#000000",
    font: "10px sans-serif",
    textAlign: "start",
    textBaseline: "alphabetic",
    globalAlpha: 1.0,
    globalCompositeOperation: "source-over",
    lineWidth: 1.0,
    lineCap: "butt",
    lineJoin: "miter",
    miterLimit: 10,
    shadowBlur: 0,
    shadowColor: "rgba(0, 0, 0, 0)",
    shadowOffsetX: 0,
    shadowOffsetY: 0,
    lineDashOffset: 0,
    imageSmoothingEnabled: true,
    imageSmoothingQuality: "low",
    direction: "ltr",
    filter: "none",
    letterSpacing: "0px",
    wordSpacing: "0px",
    fontKerning: "auto",
    fontStretch: "normal",
    fontVariantCaps: "normal",
    textRendering: "auto",

    fillRect() {},
    strokeRect() {},
    clearRect() {},
    fillText() {},
    strokeText() {},
    measureText(text) {
      const len = String(text || "").length;
      const w = len * 6.5;
      return {
        width: w,
        actualBoundingBoxLeft: 0,
        actualBoundingBoxRight: w,
        fontBoundingBoxAscent: 11,
        fontBoundingBoxDescent: 3,
        actualBoundingBoxAscent: 8,
        actualBoundingBoxDescent: 2,
        emHeightAscent: 11,
        emHeightDescent: 3,
        alphabeticBaseline: 0,
        ideographicBaseline: -3,
        hangingBaseline: 8,
      };
    },
    beginPath() {},
    closePath() {},
    moveTo() {},
    lineTo() {},
    bezierCurveTo() {},
    quadraticCurveTo() {},
    arc() {},
    arcTo() {},
    ellipse() {},
    rect() {},
    roundRect() {},
    fill() {},
    stroke() {},
    clip() {},
    save() {},
    restore() {},
    translate() {},
    rotate() {},
    scale() {},
    transform() {},
    setTransform() { return this; },
    getTransform() { return { a: 1, b: 0, c: 0, d: 1, e: 0, f: 0, is2D: true, isIdentity: true }; },
    resetTransform() {},
    drawImage() {},
    createLinearGradient() { return { addColorStop() {} }; },
    createRadialGradient() { return { addColorStop() {} }; },
    createConicGradient() { return { addColorStop() {} }; },
    createPattern() { return {}; },
    createImageData(sw, sh) {
      const w = typeof sw === "number" ? sw : 1;
      const h = typeof sh === "number" ? sh : 1;
      return { data: new Uint8ClampedArray(w * h * 4), width: w, height: h, colorSpace: "srgb" };
    },
    getImageData(sx, sy, sw, sh) {
      const w = sw || 1;
      const h = sh || 1;
      const data = new Uint8ClampedArray(w * h * 4);
      _fillSeededByteArray(data, `canvas2d-imagedata:${w}x${h}:${sx || 0}:${sy || 0}`);
      return { data, width: w, height: h, colorSpace: "srgb" };
    },
    putImageData() {},
    setLineDash() {},
    getLineDash() { return []; },
    isPointInPath() { return false; },
    isPointInStroke() { return false; },
    getContextAttributes() { return { alpha: true, colorSpace: "srgb", desynchronized: false, willReadFrequently: false }; },
    reset() {},
  };
  return ctx;
}

// ========== DOM 元素工厂 ==========

function measureElementText(text, fontFamily, fontSize) {
  const family = String(fontFamily || "").toLowerCase();
  let widthScale = 1;
  let lineHeight = 1.2;
  if (family.includes("georgia")) {
    widthScale = 0.9915;
    lineHeight = 1.15;
  } else if (family.includes("helvetica") || family.includes("arial")) {
    widthScale = 0.9731;
    lineHeight = 1.09;
  } else if (family.includes("impact")) {
    widthScale = 1.05;
    lineHeight = 1.3;
  } else if (family.includes("times new roman")) {
    widthScale = 0.95;
    lineHeight = 1.125;
  }

  let emWidth = 0;
  const normalizedText = String(text || "").normalize("NFD");
  for (const char of normalizedText) {
    if (/[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff\ufe20-\ufe2f]/.test(char)) continue;
    if (/\s/.test(char) || /[ilIjtfr]/.test(char)) emWidth += 0.28;
    else if (/[mw]/.test(char)) emWidth += 0.78;
    else if (/[MW@%]/.test(char)) emWidth += 0.9;
    else if (/[A-Z]/.test(char)) emWidth += 0.66;
    else if (/[a-z0-9]/.test(char)) emWidth += 0.54;
    else emWidth += 1;
  }
  return {
    width: Math.round(emWidth * fontSize * widthScale * 64) / 64,
    height: Math.round(fontSize * lineHeight),
  };
}

function createElement(tagName) {
  const tag = String(tagName || "div").toLowerCase();
  const el = {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    nodeName: tag.toUpperCase(),
    localName: tag,
    namespaceURI: "http://www.w3.org/1999/xhtml",
    prefix: null,
    style: new Proxy({}, {
      get(_t, p) {
        if (typeof p !== "string") return undefined;
        return Object.prototype.hasOwnProperty.call(_t, p) ? _t[p] : "";
      },
      set(_t, p, v) { _t[p] = v; return true; },
    }),
    children: [],
    childNodes: [],
    attributes: [],
    parentNode: null,
    parentElement: null,
    firstChild: null,
    lastChild: null,
    nextSibling: null,
    previousSibling: null,
    classList: {
      _list: [],
      add(...cls) { for (const c of cls) if (!this._list.includes(c)) this._list.push(c); },
      remove(...cls) { this._list = this._list.filter((x) => !cls.includes(x)); },
      contains(c) { return this._list.includes(c); },
      toggle(c) { if (this.contains(c)) { this.remove(c); return false; } this.add(c); return true; },
      get length() { return this._list.length; },
      item(i) { return this._list[i] || null; },
      toString() { return this._list.join(" "); },
    },
    dataset: {},
    id: "",
    className: "",
    innerHTML: "",
    outerHTML: `<${tag}></${tag}>`,
    textContent: "",
    innerText: "",
    src: "",
    href: "",
    type: "",
    rel: "",
    crossOrigin: null,
    width: tag === "canvas" ? 300 : 0,
    height: tag === "canvas" ? 150 : 0,
    offsetWidth: 0,
    offsetHeight: 0,
    clientWidth: 0,
    clientHeight: 0,
    scrollWidth: 0,
    scrollHeight: 0,
    scrollTop: 0,
    scrollLeft: 0,
    _contexts: {},
    _attrs: {},
    appendChild(child) {
      this.children.push(child);
      this.childNodes.push(child);
      if (child && typeof child === "object") child.parentNode = this;
      return child;
    },
    removeChild(child) {
      this.children = this.children.filter((x) => x !== child);
      this.childNodes = this.childNodes.filter((x) => x !== child);
      return child;
    },
    insertBefore(newChild) { this.children.push(newChild); this.childNodes.push(newChild); return newChild; },
    replaceChild(newChild, oldChild) { this.removeChild(oldChild); this.appendChild(newChild); return oldChild; },
    cloneNode() { return createElement(tag); },
    setAttribute(name, value) { this._attrs[name] = String(value); if (name === "id") this.id = String(value); },
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(this._attrs, name) ? this._attrs[name] : null; },
    hasAttribute(name) { return Object.prototype.hasOwnProperty.call(this._attrs, name); },
    removeAttribute(name) { delete this._attrs[name]; },
    focus() {},
    blur() {},
    click() {},
    contains() { return false; },
    matches() { return false; },
    closest() { return null; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    getElementsByTagName() { return []; },
    getElementsByClassName() { return []; },
    after() {},
    before() {},
    remove() {},
    append() {},
    prepend() {},
    replaceWith() {},
    getBoundingClientRect() {
      const text = this.innerText || this.textContent || "";
      const fontSize = Number.parseFloat(this.style.fontSize) || 16;
      const measured = text ? measureElementText(text, this.style.fontFamily, fontSize) : { width: 0, height: 0 };
      const w = this.width || this.clientWidth || measured.width;
      const h = this.height || this.clientHeight || measured.height;
      return { x: 0, y: 0, width: w, height: h, top: 0, right: w, bottom: h, left: 0 };
    },
    getAnimations() { return []; },
    animate() { return { finished: Promise.resolve(), cancel() {}, play() {}, pause() {} }; },

    // Canvas 专属方法
    getContext(type) {
      if (tag !== "canvas") return null;
      const t = String(type || "").toLowerCase();
      if (this._contexts[t]) return this._contexts[t];
      if (t === "2d") {
        const ctx = createCanvas2DContext(this);
        this._contexts[t] = ctx;
        return ctx;
      }
      if (t === "webgl" || t === "experimental-webgl") {
        const ctx = createWebGLContext(1, _runtimePayload);
        ctx.canvas = this;
        this._contexts["webgl"] = ctx;
        return ctx;
      }
      if (t === "webgl2" || t === "experimental-webgl2") {
        const ctx = createWebGLContext(2, _runtimePayload);
        ctx.canvas = this;
        this._contexts["webgl2"] = ctx;
        return ctx;
      }
      if (t === "bitmaprenderer") {
        const ctx = { canvas: this, transferFromImageBitmap() {} };
        this._contexts[t] = ctx;
        return ctx;
      }
      return null;
    },
    toDataURL(_type) {
      if (tag !== "canvas") return "";
      return _seededCanvasDataUrl(`canvas-todataurl:${this.width || 0}x${this.height || 0}`);
    },
    toBlob(callback, type) {
      if (typeof callback === "function") {
        const b = typeof Blob !== "undefined" ? new Blob([], { type: type || "image/png" }) : {};
        callback(b);
      }
    },
    transferControlToOffscreen() {
      return { width: this.width, height: this.height, getContext: this.getContext.bind(this) };
    },
  };

  // iframe 特殊属性
  if (tag === "iframe") {
    el.contentWindow = null;
    el.contentDocument = null;
    el.sandbox = { add() {}, remove() {}, contains() { return false; }, toString() { return ""; } };
  }

  return installEventTarget(el);
}

// ========== 主运行时安装 ==========

function installRuntime(payload) {
  const routeProfile = _resolveRouteProfile(payload);
  const runtimeState = _createRuntimeState(payload, routeProfile);
  const browserProfile = routeProfile.browserProfile || "chrome";
  const isSafari = browserProfile === "safari";
  _runtimePayload = {
    ...payload,
    host_page_url: routeProfile.hostPageUrl,
    route_profile_name: routeProfile.name,
    browser_profile: browserProfile,
  };

  const mathObject = Object.create(globalThis.Math || Math);
  Object.defineProperty(mathObject, "random", {
    value: () => runtimeState.prng.next(),
    writable: true,
    configurable: true,
    enumerable: false,
  });
  globalThis.Math = mathObject;

  const sdkVersion = String(payload.sdk_version || "20260810913b");
  const hostPageUrl = routeProfile.hostPageUrl;
  const versionedSdkUrl = String(
    payload.enforcement_sdk_url
      || (/\/sentinel\/[^/]+\/sdk\.js$/i.test(String(payload.sdk_url || "")) ? payload.sdk_url : "")
      || `https://sentinel.openai.com/sentinel/${sdkVersion}/sdk.js`
  );
  const sdkUrl = routeProfile.name === "oauth_create_account"
    ? String(payload.requirements_sdk_url || AUTH_SENTINEL_SDK_URL)
    : String(payload.sdk_url || versionedSdkUrl);
  const chatBuild = String(payload.chat_build || routeProfile.sdkBuild || "");
  _runtimePayload.sdk_url = sdkUrl;
  _runtimePayload.enforcement_sdk_url = versionedSdkUrl;
  let hostOrigin = "https://auth.openai.com";
  let hostName = "auth.openai.com";
  try {
    const parsedHostPage = new URL(hostPageUrl);
    hostOrigin = parsedHostPage.origin;
    hostName = parsedHostPage.hostname;
  } catch (_) {}
  const isMac = payload.is_mac != null
    ? Boolean(payload.is_mac)
    : isSafari || /mac/i.test(String(payload.navigator_platform || payload.user_agent || ""));
  const colorDepth = Number(payload.color_depth || 24);
  const dpr = Number(payload.device_pixel_ratio || (isMac ? 2 : 1));
  const screenW = Number(payload.screen_width || 1920);
  const screenH = Number(payload.screen_height || 1080);
  // Mac 菜单栏约 25px，Windows 任务栏约 40px
  const availH = isMac ? screenH - 25 : screenH - 40;
  const toolbarH = isMac ? 37 : 79;

  // ---- screen ----
  const screen = {
    width: screenW,
    height: screenH,
    availWidth: screenW,
    availHeight: availH,
    availLeft: 0,
    availTop: isMac ? 25 : 0,
    colorDepth,
    pixelDepth: colorDepth,
    orientation: { type: "landscape-primary", angle: 0, onchange: null },
    isExtended: false,
  };

  // ---- scripts / DOM ----
  let scripts;
  let sdkScriptEl;
  if (routeProfile.name === "chat_requirements") {
    scripts = [];
    sdkScriptEl = null;
  } else {
    const scriptUrls = Array.isArray(routeProfile.scriptUrls) && routeProfile.scriptUrls.length
      ? routeProfile.scriptUrls.slice()
      : [sdkUrl];
    if (!scriptUrls.includes(sdkUrl)) scriptUrls.unshift(sdkUrl);
    scripts = scriptUrls.map((src) => {
      const scriptEl = createElement("script");
      scriptEl.src = src;
      scriptEl.type = "text/javascript";
      return scriptEl;
    });
    sdkScriptEl = scripts.find((scriptEl) => scriptEl.src === sdkUrl);
  }
  const documentElement = createElement("html");
  const documentHeight = Math.max(
    screenH + 1,
    Math.floor(Number(payload.document_height || screenH * 1.6)),
  );
  if (chatBuild) documentElement.setAttribute("data-build", chatBuild);
  documentElement.clientWidth = screenW;
  documentElement.clientHeight = screenH;
  documentElement.scrollWidth = screenW;
  documentElement.scrollHeight = documentHeight;

  const bodyEl = createElement("body");
  bodyEl.clientWidth = screenW;
  bodyEl.clientHeight = screenH;
  bodyEl.scrollWidth = screenW;
  bodyEl.scrollHeight = documentHeight;

  const headEl = createElement("head");

  // ---- document ----
  const document = {
    nodeType: 9,
    readyState: "complete",
    hidden: false,
    visibilityState: "visible",
    hasFocus() { return true; },
    referrer: "",
    URL: hostPageUrl,
    documentURI: hostPageUrl,
    baseURI: hostPageUrl,
    domain: hostName,
    cookie: `oai-did=${encodeURIComponent(payload.device_id || "")}`,
    characterSet: "UTF-8",
    charset: "UTF-8",
    inputEncoding: "UTF-8",
    contentType: "text/html",
    doctype: { name: "html", publicId: "", systemId: "" },
    compatMode: "CSS1Compat",
    designMode: "off",
    dir: "ltr",
    title: "",
    lastModified: "",
    scripts,
    forms: [],
    images: [],
    links: [],
    embeds: [],
    plugins: [],
    styleSheets: [],
    fonts: {
      ready: Promise.resolve(),
      status: "loaded",
      check() { return true; },
      load() { return Promise.resolve([]); },
      forEach() {},
      entries() { return [][Symbol.iterator](); },
      keys() { return [][Symbol.iterator](); },
      values() { return [][Symbol.iterator](); },
      [Symbol.iterator]() { return [][Symbol.iterator](); },
      get size() { return 0; },
      has() { return false; },
      add() {},
      delete() { return false; },
      clear() {},
      addEventListener() {},
      removeEventListener() {},
      dispatchEvent() { return true; },
      onloading: null,
      onloadingdone: null,
      onloadingerror: null,
    },
    currentScript: sdkScriptEl,
    implementation: {
      createDocument() { return {}; },
      createDocumentType() { return {}; },
      createHTMLDocument() { return {}; },
      hasFeature() { return true; },
    },
    documentElement,
    body: bodyEl,
    head: headEl,
    defaultView: null, // 设为 globalThis，在下面赋值
    activeElement: bodyEl,
    fullscreenElement: null,
    pointerLockElement: null,

    createElement(tag) {
      const el = createElement(tag);
      if (String(tag).toLowerCase() === "script") scripts.push(el);
      return el;
    },
    createElementNS(_ns, tag) { return this.createElement(tag); },
    createDocumentFragment() {
      return { nodeType: 11, children: [], childNodes: [], appendChild(c) { this.children.push(c); return c; }, removeChild(c) { this.children = this.children.filter(x => x !== c); return c; }, querySelector() { return null; }, querySelectorAll() { return []; } };
    },
    createTextNode(text) { return { nodeType: 3, textContent: String(text || ""), data: String(text || "") }; },
    createComment(text) { return { nodeType: 8, textContent: String(text || ""), data: String(text || "") }; },
    createEvent(type) { return { type, initEvent() {} }; },
    createRange() {
      return { setStart() {}, setEnd() {}, collapse() {}, cloneRange() { return this; }, getBoundingClientRect() { return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 }; }, getClientRects() { return []; } };
    },
    createTreeWalker() { return { nextNode() { return null; } }; },
    createNodeIterator() { return { nextNode() { return null; } }; },
    adoptNode(n) { return n; },
    importNode(n) { return n; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    getElementById() { return null; },
    getElementsByTagName(tag) { if (tag === "script") return scripts; return []; },
    getElementsByClassName() { return []; },
    getElementsByName() { return []; },
    evaluate() { return { iterateNext() { return null; }, snapshotLength: 0 }; },
    exitFullscreen() { return Promise.resolve(); },
    exitPointerLock() {},
    getSelection() { return { rangeCount: 0, addRange() {}, removeAllRanges() {}, getRangeAt() { return null; } }; },
    elementFromPoint() { return null; },
    elementsFromPoint() { return []; },
    caretPositionFromPoint() { return null; },
  };
  installEventTarget(document);
  document.defaultView = globalThis;
  // document.location 必须和 window.location 指向同一对象（下面 globalThis.location 赋值后回写）
  // 在 globalThis.location 赋值之后通过 defineProperty 绑定
  Object.defineProperty(document, "location", {
    get() { return globalThis.location; },
    set(v) { globalThis.location = v; },
    configurable: true,
    enumerable: true,
  });

  // ---- performance ----
  const monotonicStartMs = Number(_nodeProcess.hrtime.bigint()) / 1e6;
  const configuredPerfNow = Number.isFinite(Number(runtimeState.perf_now))
    ? Number(runtimeState.perf_now)
    : 0;
  const wallClockPerfNow = _RealDate.now() - Number(runtimeState.time_origin);
  const initialPerfNow = Math.max(
    configuredPerfNow,
    Number.isFinite(wallClockPerfNow) ? wallClockPerfNow : configuredPerfNow,
  );
  let _perfNow = initialPerfNow;
  const currentPerfNow = () => {
    const elapsedMs = Math.max(0, Number(_nodeProcess.hrtime.bigint()) / 1e6 - monotonicStartMs);
    _perfNow = Math.max(_perfNow, initialPerfNow + elapsedMs);
    runtimeState.perf_now = _perfNow;
    runtimeState.wall_time_ms = Math.round(runtimeState.time_origin + _perfNow);
    return _perfNow;
  };
  const heapLimit = Number(payload.js_heap_size_limit || 4294705152);
  const performance = {
    now() {
      return currentPerfNow();
    },
    timeOrigin: Number(runtimeState.time_origin),
    navigation: { type: 0, redirectCount: 0 },
    getEntries() { return []; },
    getEntriesByName() { return []; },
    getEntriesByType() { return []; },
    mark() { return {}; },
    measure() { return {}; },
    clearMarks() {},
    clearMeasures() {},
    clearResourceTimings() {},
    setResourceTimingBufferSize() {},
    addEventListener() {},
    removeEventListener() {},
  };
  if (!isSafari) {
    performance.memory = {
      jsHeapSizeLimit: heapLimit,
      totalJSHeapSize: Number(runtimeState.heap_total_js),
      usedJSHeapSize: Number(runtimeState.heap_used_js),
    };
  }

  const RealDate = _RealDate;
  const requestedTimezone = String(payload.timezone || _nodeProcess.env.TZ || "").trim();
  let timezoneNameFormatter = null;
  if (requestedTimezone) {
    try {
      const requestedTimezoneFormatter = new _RealIntlDateTimeFormat("en-US", {
        timeZone: requestedTimezone,
        timeZoneName: "long",
      });
      _nodeProcess.env.TZ = requestedTimezone;
      if (requestedTimezone.startsWith("America/")) {
        timezoneNameFormatter = requestedTimezoneFormatter;
      }
    } catch (_) {}
  }
  class SentinelDate extends RealDate {
    constructor(...args) {
      super(...(args.length ? args : [SentinelDate.now()]));
    }
    static now() {
      return Math.round(performance.timeOrigin + currentPerfNow());
    }
    toString() {
      const value = RealDate.prototype.toString.call(this);
      if (!timezoneNameFormatter) return value;
      const timezoneName = timezoneNameFormatter.formatToParts(this)
        .find(part => part.type === "timeZoneName");
      return timezoneName ? value.replace(/\s\([^)]*\)$/, ` (${timezoneName.value})`) : value;
    }
  }
  SentinelDate.UTC = RealDate.UTC.bind(RealDate);
  SentinelDate.parse = RealDate.parse.bind(RealDate);
  globalThis.Date = SentinelDate;

  // ---- Polyfills ----
  class TextEncoderPoly {
    get encoding() { return "utf-8"; }
    encode(text) {
      const str = String(text || "");
      const out = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i += 1) out[i] = str.charCodeAt(i) & 255;
      return out;
    }
    encodeInto(src, dest) { const e = this.encode(src); dest.set(e.subarray(0, dest.length)); return { read: Math.min(src.length, dest.length), written: Math.min(e.length, dest.length) }; }
  }

  class TextDecoderPoly {
    constructor(label) { this._label = label || "utf-8"; }
    get encoding() { return this._label; }
    decode(input) {
      if (!input) return "";
      let out = "";
      for (let i = 0; i < input.length; i += 1) out += String.fromCharCode(input[i]);
      return out;
    }
  }

  class URLSearchParamsPoly {
    constructor(search) {
      this._pairs = [];
      const s = String(search || "").replace(/^\?/, "");
      if (!s) return;
      for (const p of s.split("&")) {
        if (!p) continue;
        const i = p.indexOf("=");
        if (i < 0) this._pairs.push([decodeURIComponent(p), ""]);
        else this._pairs.push([decodeURIComponent(p.slice(0, i)), decodeURIComponent(p.slice(i + 1))]);
      }
    }
    get(name) { const p = this._pairs.find(x => x[0] === name); return p ? p[1] : null; }
    has(name) { return this._pairs.some(x => x[0] === name); }
    keys() { return this._pairs.map(x => x[0])[Symbol.iterator](); }
    values() { return this._pairs.map(x => x[1])[Symbol.iterator](); }
    entries() { return this._pairs[Symbol.iterator](); }
    forEach(cb) { this._pairs.forEach(([k, v]) => cb(v, k, this)); }
    toString() { return this._pairs.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&"); }
    [Symbol.iterator]() { return this.entries(); }
  }

  class URLPoly {
    constructor(input, base) {
      const raw = String(input || "");
      if (/^https?:\/\//i.test(raw)) { this.href = raw; }
      else {
        const b = String(base || "https://auth.openai.com/").replace(/\/$/, "");
        this.href = `${b}/${raw.replace(/^\//, "")}`;
      }
      const m = this.href.match(/^(https?:)\/\/([^/:]+)(:\d+)?(\/[^?#]*)?(\?[^#]*)?(#.*)?$/i);
      this.protocol = m ? m[1] : "https:";
      this.host = m ? m[2] + (m[3] || "") : "auth.openai.com";
      this.hostname = m ? m[2] : "auth.openai.com";
      this.port = m && m[3] ? m[3].slice(1) : "";
      this.pathname = m && m[4] ? m[4] : "/";
      this.search = m && m[5] ? m[5] : "";
      this.hash = m && m[6] ? m[6] : "";
      this.origin = `${this.protocol}//${this.host}`;
      this.searchParams = new URLSearchParamsPoly(this.search);
      this.username = "";
      this.password = "";
    }
    toString() { return this.href; }
    toJSON() { return this.href; }
  }

  // ---- 全局对象赋值 ----
  globalThis.window = globalThis;
  globalThis.self = globalThis;
  globalThis.top = globalThis;
  globalThis.parent = globalThis;
  globalThis.frames = globalThis;
  globalThis.length = 0;
  globalThis.document = document;
  globalThis.innerWidth = screenW;
  globalThis.innerHeight = screenH;
  globalThis.outerWidth = screenW;
  globalThis.outerHeight = screenH + toolbarH;
  globalThis.devicePixelRatio = dpr;
  globalThis.screenX = 0;
  globalThis.screenY = 0;
  globalThis.screenLeft = 0;
  globalThis.screenTop = 0;
  globalThis.pageXOffset = 0;
  globalThis.pageYOffset = 0;
  globalThis.scrollX = 0;
  globalThis.scrollY = 0;
  globalThis.isSecureContext = true;
  globalThis.origin = hostOrigin;
  globalThis.crossOriginIsolated = false;
  globalThis.visualViewport = {
    width: screenW, height: screenH,
    offsetLeft: 0, offsetTop: 0, pageLeft: 0, pageTop: 0,
    scale: 1, onresize: null, onscroll: null,
    addEventListener() {}, removeEventListener() {},
  };

  // Node 22+ 内置只读 navigator/performance/location，必须先 delete 才能赋值
  try { delete globalThis.navigator; } catch (_) {}
  try { delete globalThis.performance; } catch (_) {}
  try { delete globalThis.location; } catch (_) {}

  // ---- navigator ----
  const hwConcurrency = Number(payload.hardware_concurrency || 8);
  const devMemory = Number(payload.device_memory || 8);
  const navPlatform = String(payload.navigator_platform || (isSafari ? "MacIntel" : "Win32"));
  const navVendor = String(payload.navigator_vendor || (isSafari ? "Apple Computer, Inc." : "Google Inc."));
  const userLang = String(payload.language || "en-US");
  const userLangs = Array.isArray(payload.languages) && payload.languages.length
    ? payload.languages : ["en-US", "en"];
  Object.freeze(userLangs);

  // Chrome 内置 PDF 插件
  const pdfPlugin = {
    name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format",
    length: 1, 0: { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format" },
    item(i) { return i === 0 ? this[0] : null; },
    namedItem(n) { return n === "application/pdf" ? this[0] : null; },
  };
  const chromePdfPlugin = { ...pdfPlugin, name: "Chrome PDF Viewer" };
  const chromiumPdfPlugin = { ...pdfPlugin, name: "Chromium PDF Viewer" };
  const edgePdfPlugin = { ...pdfPlugin, name: "Microsoft Edge PDF Viewer" };
  const webkitPdfPlugin = { ...pdfPlugin, name: "WebKit built-in PDF" };

  const pluginsArray = isSafari
    ? []
    : [pdfPlugin, chromePdfPlugin, chromiumPdfPlugin, edgePdfPlugin, webkitPdfPlugin];
  const pluginsList = {
    length: pluginsArray.length,
    item(i) { return pluginsArray[i] || null; },
    namedItem(name) { return pluginsArray.find(p => p.name === name) || null; },
    refresh() {},
    [Symbol.iterator]() { return pluginsArray[Symbol.iterator](); },
  };
  for (let i = 0; i < pluginsArray.length; i++) pluginsList[i] = pluginsArray[i];

  const mimeTypePdf = { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format", enabledPlugin: pdfPlugin };
  const mimeTypeText = { type: "text/pdf", suffixes: "pdf", description: "Portable Document Format", enabledPlugin: pdfPlugin };
  const mimeTypesArray = isSafari ? [] : [mimeTypePdf, mimeTypeText];
  const mimesList = {
    length: mimeTypesArray.length,
    item(i) { return mimeTypesArray[i] || null; },
    namedItem(name) { return mimeTypesArray.find(mime => mime.type === name) || null; },
    [Symbol.iterator]() { return mimeTypesArray[Symbol.iterator](); },
    [Symbol.toStringTag]: "MimeTypeArray",
  };
  for (let i = 0; i < mimeTypesArray.length; i++) mimesList[i] = mimeTypesArray[i];

  // SDK uses Object.getPrototypeOf(navigator) to pick properties, so all nav props go on prototype
  const NavigatorProto = {
    vendorSub: "",
    productSub: "20030107",
    vendor: navVendor,
    maxTouchPoints: Number(payload.max_touch_points || 0),
    scheduling: { isInputPending() { return false; } },
    userActivation: { hasBeenActive: true, isActive: false },
    doNotTrack: null,
    geolocation: {
      getCurrentPosition(_s, err) { if (typeof err === "function") err({ code: 1, message: "User denied Geolocation" }); },
      watchPosition(_s, err) { if (typeof err === "function") err({ code: 1, message: "User denied Geolocation" }); return 0; },
      clearWatch() {},
    },
    connection: {
      effectiveType: "4g",
      rtt: 50,
      downlink: 10,
      saveData: false,
      onchange: null,
      addEventListener() {},
      removeEventListener() {},
    },
    plugins: pluginsList,
    mimeTypes: mimesList,
    pdfViewerEnabled: true,
    webkitTemporaryStorage: {
      queryUsageAndQuota(cb) { if (typeof cb === "function") cb(0, 120000000000); },
      [Symbol.toStringTag]: "DeprecatedStorageQuota",
    },
    webkitPersistentStorage: {
      queryUsageAndQuota(cb) { if (typeof cb === "function") cb(0, 0); },
      requestQuota(_bytes, cb) { if (typeof cb === "function") cb(0); },
      [Symbol.toStringTag]: "DeprecatedStorageQuota",
    },
    hardwareConcurrency: hwConcurrency,
    cookieEnabled: true,
    credentials: {
      create() { return Promise.reject(new Error("NotSupportedError")); },
      get() { return Promise.reject(new Error("NotSupportedError")); },
      store() { return Promise.resolve(); },
      preventSilentAccess() { return Promise.resolve(); },
    },
    mediaDevices: {
      enumerateDevices() { return Promise.resolve([]); },
      getUserMedia() { return Promise.reject(new Error("NotAllowedError")); },
      getDisplayMedia() { return Promise.reject(new Error("NotAllowedError")); },
      getSupportedConstraints() { return { width: true, height: true, aspectRatio: true, frameRate: true, facingMode: true, deviceId: true, groupId: true }; },
      addEventListener() {},
      removeEventListener() {},
      ondevicechange: null,
    },
    permissions: {
      query() { return Promise.resolve({ state: "prompt", onchange: null, addEventListener() {}, removeEventListener() {} }); },
    },
    locks: {
      request() { return Promise.resolve(); },
      query() { return Promise.resolve({ held: [], pending: [] }); },
    },
    ink: {
      requestPresenter() { return Promise.resolve({ updateInkTrailStartPoint() {}, expectedImprovement: 0 }); },
    },

    // 基础属性
    userAgent: String(payload.user_agent || "Mozilla/5.0"),
    appCodeName: "Mozilla",
    appName: "Netscape",
    appVersion: String(payload.user_agent || "5.0").replace(/^Mozilla\//, ""),
    product: "Gecko",
    language: userLang,
    languages: userLangs,
    platform: navPlatform,
    deviceMemory: devMemory,
    webdriver: false,
    onLine: true,
    javaEnabled() { return false; },
    getGamepads() { return [null, null, null, null]; },
    sendBeacon() { return true; },
    vibrate() { return false; },
    getBattery() { return Promise.resolve({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1, onchargingchange: null, onchargingtimechange: null, ondischargingtimechange: null, onlevelchange: null, addEventListener() {}, removeEventListener() {} }); },
    requestMediaKeySystemAccess() { return Promise.reject(new Error("NotSupportedError")); },
    clipboard: {
      read() { return Promise.reject(new Error("NotAllowedError")); },
      readText() { return Promise.reject(new Error("NotAllowedError")); },
      write() { return Promise.reject(new Error("NotAllowedError")); },
      writeText() { return Promise.reject(new Error("NotAllowedError")); },
      [Symbol.toStringTag]: "Clipboard",
    },
    storage: {
      estimate() { return Promise.resolve({ quota: 300000000000, usage: 0 }); },
      persist() { return Promise.resolve(false); },
      persisted() { return Promise.resolve(false); },
      getDirectory() { return Promise.reject(new Error("NotSupportedError")); },
    },
    serviceWorker: {
      controller: null,
      ready: new Promise(() => {}),
      register() { return Promise.reject(new Error("SecurityError")); },
      getRegistration() { return Promise.resolve(undefined); },
      getRegistrations() { return Promise.resolve([]); },
      addEventListener() {},
      removeEventListener() {},
      oncontrollerchange: null,
      onmessage: null,
    },
    keyboard: { lock() { return Promise.resolve(); }, unlock() {}, [Symbol.toStringTag]: "Keyboard" },
    managed: { [Symbol.toStringTag]: "NavigatorManagedData" },
    virtualKeyboard: { show() {}, hide() {}, overlaysContent: false, boundingRect: { x: 0, y: 0, width: 0, height: 0 }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "VirtualKeyboard" },
    wakeLock: { request() { return Promise.reject(new Error("NotAllowedError")); }, [Symbol.toStringTag]: "WakeLock" },
    storageBuckets: { open() { return Promise.reject(new Error("NotSupportedError")); }, [Symbol.toStringTag]: "StorageBucketManager" },
    mediaSession: { metadata: null, playbackState: "none", setActionHandler() {}, setPositionState() {}, [Symbol.toStringTag]: "MediaSession" },
    mediaCapabilities: { decodingInfo() { return Promise.resolve({ supported: true, smooth: true, powerEfficient: true }); }, encodingInfo() { return Promise.resolve({ supported: true, smooth: true, powerEfficient: true }); }, [Symbol.toStringTag]: "MediaCapabilities" },
    presentation: { defaultRequest: null, receiver: null, [Symbol.toStringTag]: "Presentation" },
    login: { setStatus() { return Promise.resolve(); }, [Symbol.toStringTag]: "NavigatorLogin" },
    devicePosture: { type: "continuous", addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "DevicePosture" },
    xr: { isSessionSupported() { return Promise.resolve(false); }, requestSession() { return Promise.reject(new Error("NotSupportedError")); }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "XRSystem" },
    gpu: { requestAdapter() { return Promise.resolve(null); }, getPreferredCanvasFormat() { return "bgra8unorm"; }, [Symbol.toStringTag]: "GPU" },
    serial: { getPorts() { return Promise.resolve([]); }, requestPort() { return Promise.reject(new Error("NotFoundError")); }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "Serial" },
    hid: { getDevices() { return Promise.resolve([]); }, requestDevice() { return Promise.reject(new Error("NotFoundError")); }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "HID" },
    usb: { getDevices() { return Promise.resolve([]); }, requestDevice() { return Promise.reject(new Error("NotFoundError")); }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "USB" },
    bluetooth: { getAvailability() { return Promise.resolve(false); }, requestDevice() { return Promise.reject(new Error("NotFoundError")); }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "Bluetooth" },
    windowControlsOverlay: { visible: false, getTitlebarAreaRect() { return { x: 0, y: 0, width: 0, height: 0 }; }, addEventListener() {}, removeEventListener() {}, [Symbol.toStringTag]: "WindowControlsOverlay" },
    deprecatedRunAdAuctionEnforcesKAnonymity: false,
    protectedAudience: { [Symbol.toStringTag]: "ProtectedAudience" },
  };
  if (isSafari) {
    for (const key of _safariUnsupportedNavigatorKeys(payload)) {
      delete NavigatorProto[key];
    }
  } else {
    NavigatorProto.userAgentData = (() => {
      const uaMajor = String(payload.user_agent || "").match(/Chrome\/(\d+)/)?.[1] || "131";
      const secChUa = String(payload.sec_ch_ua || "");
      let brands;
      if (secChUa) {
        brands = secChUa.split(",").map(s => {
          const m = s.trim().match(/^"([^"]+)";\s*v="([^"]+)"/);
          return m ? { brand: m[1], version: m[2] } : null;
        }).filter(Boolean);
      }
      if (!brands || !brands.length) {
        brands = [
          { brand: "Chromium", version: uaMajor },
          { brand: "Google Chrome", version: uaMajor },
          { brand: "Not-A.Brand", version: "8" },
        ];
      }
      const isLinux = /linux/i.test(String(payload.navigator_platform || payload.user_agent || ""));
      const plat = String(
        payload.sec_ch_ua_platform || (isMac ? "macOS" : (isLinux ? "Linux" : "Windows"))
      ).replace(/"/g, "");
      const defaultPlatformVersion = isMac ? "10.15.7" : (isLinux ? "0.0.0" : "10.0.0");
      const platVer = String(payload.sec_ch_ua_platform_version || defaultPlatformVersion).replace(/"/g, "");
      const defaultArch = isMac && /Apple M\d/i.test(String(payload.gpu_renderer || "")) ? "arm" : "x86";
      const arch = String(payload.sec_ch_ua_arch || defaultArch).replace(/"/g, "");
      const bitness = String(payload.sec_ch_ua_bitness || "64").replace(/"/g, "");
      const fullVer = String(payload.sec_ch_ua_full_version || `${uaMajor}.0.0.0`).replace(/"/g, "");
      const fullListValue = String(payload.sec_ch_ua_full_version_list || "");
      const parsedFullVersionList = fullListValue.split(",").map(s => {
        const m = s.trim().match(/^"([^"]+)";\s*v="([^"]+)"/);
        return m ? { brand: m[1], version: m[2] } : null;
      }).filter(Boolean);
      const fullVersionList = parsedFullVersionList.length
        ? parsedFullVersionList
        : brands.map(b => ({
          brand: b.brand,
          version: fullVer.startsWith(b.version) ? fullVer : b.version + ".0.0.0",
        }));
      return {
        brands,
        mobile: false,
        platform: plat,
        getHighEntropyValues() {
          return Promise.resolve({
            brands, mobile: false, platform: plat,
            platformVersion: platVer, architecture: arch, bitness,
            model: "", uaFullVersion: fullVer, fullVersionList,
          });
        },
        toJSON() { return { brands: this.brands, mobile: this.mobile, platform: this.platform }; },
      };
    })();
  }
  const orderedNavigatorProto = _buildOrderedObject(
    runtimeState.navigator_proto_own_keys,
    NavigatorProto,
    (key) => _makeNavigatorFallbackValue(key, payload)
  );
  globalThis.navigator = Object.create(orderedNavigatorProto);

  // ---- location (模拟 auth.openai.com 宿主页面) ----
  const parsedHostUrl = new (globalThis.URL || URLPoly)(hostPageUrl);
  const updateLocation = (nextUrl) => {
    const parsed = new (globalThis.URL || URLPoly)(String(nextUrl || ""), globalThis.location && globalThis.location.href);
    const href = parsed.href || String(nextUrl || "");
    Object.assign(globalThis.location, {
      href,
      origin: parsed.origin || hostOrigin,
      hostname: parsed.hostname || hostName,
      host: parsed.host || hostName,
      protocol: parsed.protocol || "https:",
      pathname: parsed.pathname || "/",
      search: parsed.search || "",
      hash: parsed.hash || "",
      port: parsed.port || "",
    });
    document.URL = href;
    document.documentURI = href;
    document.baseURI = href;
    globalThis.origin = globalThis.location.origin;
    _runtimePayload.host_page_url = href;
  };
  globalThis.location = {
    href: hostPageUrl,
    origin: parsedHostUrl.origin || hostOrigin,
    hostname: parsedHostUrl.hostname || hostName,
    host: parsedHostUrl.host || hostName,
    protocol: parsedHostUrl.protocol || "https:",
    pathname: parsedHostUrl.pathname || "/create-account",
    search: parsedHostUrl.search || "",
    hash: parsedHostUrl.hash || "",
    port: parsedHostUrl.port || "",
    ancestorOrigins: { length: 0, contains() { return false; }, item() { return null; } },
    assign(nextUrl) { updateLocation(nextUrl); },
    replace(nextUrl) { updateLocation(nextUrl); },
    reload() {},
    toString() { return this.href; },
  };

  globalThis.screen = screen;
  globalThis.performance = performance;
  globalThis.localStorage = createStorage(runtimeState.local_storage_keys);
  globalThis.sessionStorage = createStorage();
  globalThis.__sentinel_init_pending = [];
  globalThis.__sentinel_token_pending = [];

  // Feature detection flags expected by SDK getConfig() [18]-[24]
  // Real traffic shows all flags = 0. "cache" is NOT an own property on window in Chrome.
  // Only "caches" (CacheStorage) exists as window.caches, not "cache".
  globalThis.caches = globalThis.caches || { open() { return Promise.resolve(createStorage()); }, has() { return Promise.resolve(false); }, delete() { return Promise.resolve(false); }, keys() { return Promise.resolve([]); }, match() { return Promise.resolve(undefined); } };
  // Ensure "cache", "ai", "createPRNG", "data", "solana", "dump", "InstallTrigger" are NOT in window
  for (const k of ["cache", "ai", "createPRNG", "data", "solana", "dump", "InstallTrigger"]) {
    try { delete globalThis[k]; } catch (_) {}
  }

  const documentOwnKeys = _createDocumentOwnKeys(routeProfile, runtimeState);
  const routeDocumentOwnKeys = new Set(documentOwnKeys);
  for (const key of documentOwnKeys) {
    if (key === "location") continue;
    if (key.startsWith("_reactListening")) document[key] = true;
    else if (key.startsWith("__reactEvents$")) document[key] = new Set();
    else if (key.startsWith("__reactContainer$")) document[key] = {};
    else document[key] = {};
  }

  // 真实 Chrome 中 Object.keys(document) 只返回 React 注入的 own 属性，
  // DOM 标准属性在 Document.prototype 上不可枚举。这里将非 React 属性标为不可枚举。
  for (const key of Object.keys(document)) {
    if (routeDocumentOwnKeys.has(key)) continue;
    const desc = Object.getOwnPropertyDescriptor(document, key);
    if (desc && desc.configurable) {
      Object.defineProperty(document, key, { ...desc, enumerable: false });
    }
  }

  globalThis.__oai_so_hc = hwConcurrency;
  globalThis.__reactRouterRouteModules = {};
  globalThis.__reactRouterVersion = "7";
  globalThis.__reactRouterContext = routeProfile.name === "update_organization"
    ? { state: { loaderData: { root: {} } } }
    : {};
  globalThis.__oai_logTTI = function() {};
  globalThis.__oai_SSR_HTML = "";
  globalThis.__STATSIG_JS__ = {};
  globalThis.__STATSIG_SDK__ = {};
  globalThis.dd_rum = {};
  globalThis.DD_RUM = globalThis.dd_rum;
  globalThis.webpackChunk_N_E = [];

  const routeWindowContext = {
    hwConcurrency,
    screenW,
    screenH,
    innerH: globalThis.innerHeight,
    hostPageUrl,
  };
  for (const key of routeProfile.windowOwnKeys || []) {
    if (!(key in globalThis)) {
      globalThis[key] = _makeWindowPlaceholder(key, payload, routeWindowContext);
    }
    _setEnumerable(globalThis, key, true);
  }

  // ---- 定时器 / 事件 ----
  // Use real Node.js timers for async operations (turnstile VM needs proper setTimeout)
  let _timerId = 1;
  const _pendingTimers = new Map();
  globalThis.setTimeout = (cb, ms) => {
    const id = _timerId++;
    if (typeof cb !== "function") return id;
    if (typeof _realSetTimeout === "function") {
      const handle = _realSetTimeout(() => {
        _pendingTimers.delete(id);
        cb();
      }, ms || 0);
      _pendingTimers.set(id, handle);
    } else {
      cb();
    }
    return id;
  };
  globalThis.clearTimeout = (id) => {
    if (_pendingTimers.has(id) && typeof _realClearTimeout === "function") {
      _realClearTimeout(_pendingTimers.get(id));
      _pendingTimers.delete(id);
    }
  };
  globalThis.setInterval = (_cb, _ms) => _timerId++;
  globalThis.clearInterval = () => {};
  globalThis.requestAnimationFrame = (cb) => globalThis.setTimeout(() => {
    if (typeof cb === "function") cb(currentPerfNow());
  }, 16);
  globalThis.cancelAnimationFrame = globalThis.clearTimeout;
  globalThis.requestIdleCallback = (cb) => globalThis.setTimeout(() => {
    const startedAt = currentPerfNow();
    if (typeof cb === "function") {
      cb({
        didTimeout: false,
        timeRemaining: () => Math.max(0, 50 - (currentPerfNow() - startedAt)),
      });
    }
  }, 1);
  globalThis.cancelIdleCallback = globalThis.clearTimeout;
  globalThis.queueMicrotask = globalThis.queueMicrotask || ((cb) => { Promise.resolve().then(cb); });
  installEventTarget(globalThis);
  globalThis.postMessage = () => {};
  globalThis.close = () => {};
  globalThis.stop = () => {};
  globalThis.focus = () => {};
  globalThis.blur = () => {};
  globalThis.print = () => {};
  globalThis.alert = () => {};
  globalThis.confirm = () => false;
  globalThis.prompt = () => null;
  globalThis.open = () => null;
  globalThis.scroll = () => {};
  globalThis.scrollTo = () => {};
  globalThis.scrollBy = () => {};
  globalThis.getSelection = () => ({ rangeCount: 0, toString() { return ""; } });
  globalThis.find = () => false;

  // ---- 编码 / URL ----
  globalThis.atob = (input) => String.fromCharCode(...base64ToBytes(input));
  globalThis.btoa = (input) => {
    const str = String(input || "");
    const bytes = [];
    for (let i = 0; i < str.length; i += 1) bytes.push(str.charCodeAt(i) & 255);
    return bytesToBase64(bytes);
  };
  globalThis.TextEncoder = globalThis.TextEncoder || TextEncoderPoly;
  globalThis.TextDecoder = globalThis.TextDecoder || TextDecoderPoly;
  globalThis.URL = globalThis.URL || URLPoly;
  globalThis.URLSearchParams = globalThis.URLSearchParams || URLSearchParamsPoly;

  // ---- Event 类 ----
  globalThis.Event = globalThis.Event || class Event {
    constructor(type, init) { this.type = type; this.bubbles = !!(init && init.bubbles); this.cancelable = !!(init && init.cancelable); this.defaultPrevented = false; this.isTrusted = false; this.timeStamp = performance.now(); }
    preventDefault() { this.defaultPrevented = true; }
    stopPropagation() {}
    stopImmediatePropagation() {}
  };
  globalThis.CustomEvent = globalThis.CustomEvent || class CustomEvent extends globalThis.Event {
    constructor(type, init) { super(type, init); this.detail = init && Object.prototype.hasOwnProperty.call(init, "detail") ? init.detail : null; }
  };
  globalThis.ErrorEvent = globalThis.ErrorEvent || class ErrorEvent extends globalThis.Event {
    constructor(type, init) { super(type, init); this.message = (init && init.message) || ""; this.filename = (init && init.filename) || ""; this.lineno = (init && init.lineno) || 0; this.colno = (init && init.colno) || 0; this.error = (init && init.error) || null; }
  };
  globalThis.MessageEvent = globalThis.MessageEvent || class MessageEvent extends globalThis.Event {
    constructor(type, init) { super(type, init); this.data = init ? init.data : null; this.origin = init ? init.origin || "" : ""; this.lastEventId = ""; this.source = null; this.ports = []; }
  };
  globalThis.PromiseRejectionEvent = globalThis.PromiseRejectionEvent || class PromiseRejectionEvent extends globalThis.Event {
    constructor(type, init) { super(type, init); this.promise = init ? init.promise : undefined; this.reason = init ? init.reason : undefined; }
  };

  // ---- MessageChannel ----
  globalThis.MessageChannel = globalThis.MessageChannel || class MessageChannel {
    constructor() {
      this.port1 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {}, onmessage: null };
      this.port2 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {}, onmessage: null };
    }
  };
  globalThis.BroadcastChannel = globalThis.BroadcastChannel || class BroadcastChannel {
    constructor(name) { this.name = name; this.onmessage = null; }
    postMessage() {}
    close() {}
    addEventListener() {}
    removeEventListener() {}
  };

  // ---- matchMedia（智能响应常见媒体查询）----
  globalThis.matchMedia = (query) => {
    const q = String(query || "").toLowerCase();
    let matches = false;
    if (q.includes("prefers-color-scheme: light")) matches = true;
    else if (q.includes("prefers-color-scheme: dark")) matches = false;
    else if (q.includes("prefers-reduced-motion: no-preference")) matches = true;
    else if (q.includes("prefers-reduced-motion: reduce")) matches = false;
    else if (q.includes("prefers-contrast: no-preference")) matches = true;
    else if (q.includes("pointer: fine")) matches = true;
    else if (q.includes("pointer: coarse")) matches = false;
    else if (q.includes("hover: hover")) matches = true;
    else if (q.includes("hover: none")) matches = false;
    else if (q.includes("any-pointer: fine")) matches = true;
    else if (q.includes("any-hover: hover")) matches = true;
    else if (q.includes("color-gamut: srgb")) matches = true;
    else if (q.includes("color-gamut: p3")) matches = isMac;
    else if (q.includes("display-mode: browser")) matches = true;
    else if (q.includes("orientation: landscape")) matches = screenW > screenH;
    else if (q.includes("orientation: portrait")) matches = screenH > screenW;
    else {
      // 匹配 (min-width: Xpx) / (max-width: Xpx)
      const minW = q.match(/min-width:\s*(\d+)px/);
      const maxW = q.match(/max-width:\s*(\d+)px/);
      if (minW) matches = screenW >= Number(minW[1]);
      else if (maxW) matches = screenW <= Number(maxW[1]);
    }
    return {
      media: String(query || ""), matches, onchange: null,
      addListener() {}, removeListener() {},
      addEventListener() {}, removeEventListener() {},
      dispatchEvent() { return false; },
    };
  };

  // ---- getComputedStyle ----
  globalThis.getComputedStyle = (_el, _pseudo) => {
    return new Proxy({}, {
      get(_t, prop) {
        if (prop === "getPropertyValue") return (_p) => "";
        if (prop === "length") return 0;
        if (prop === "cssText") return "";
        if (typeof prop === "string") return "";
        return undefined;
      },
    });
  };

  // ---- history ----
  globalThis.history = {
    length: Number(payload.history_length || (routeProfile.name === "update_organization" ? 6 : 2)),
    state: null,
    scrollRestoration: "auto",
    back() {},
    forward() {},
    go() {},
    pushState(state, _title, nextUrl) {
      this.state = _cloneJsonValue(state);
      this.length += 1;
      if (nextUrl) updateLocation(nextUrl);
    },
    replaceState(state, _title, nextUrl) {
      this.state = _cloneJsonValue(state);
      if (nextUrl) updateLocation(nextUrl);
    },
  };
  if (runtimeState.history_state && typeof runtimeState.history_state === "object") {
    globalThis.history.replaceState(runtimeState.history_state);
  } else {
    if (!globalThis.history.state || !globalThis.history.state.key) {
      globalThis.history.replaceState({ key: Math.random().toString(32).slice(2) });
    }
    if ((globalThis.history.state || {}).idx == null) {
      globalThis.history.replaceState({ ...(globalThis.history.state || {}), idx: 0 });
    }
  }
  runtimeState.history_state = _cloneJsonValue(globalThis.history.state);

  // ---- chrome 对象（仅 Chromium）----
  if (!isSafari) {
    globalThis.chrome = {
      app: {
        isInstalled: false,
        InstallState: { DISABLED: "disabled", INSTALLED: "installed", NOT_INSTALLED: "not_installed" },
        RunningState: { CANNOT_RUN: "cannot_run", READY_TO_RUN: "ready_to_run", RUNNING: "running" },
        getDetails() { return null; },
        getIsInstalled() { return false; },
        runningState() { return "cannot_run"; },
      },
      runtime: {
        OnInstalledReason: { CHROME_UPDATE: "chrome_update", INSTALL: "install", SHARED_MODULE_UPDATE: "shared_module_update", UPDATE: "update" },
        OnRestartRequiredReason: { APP_UPDATE: "app_update", OS_UPDATE: "os_update", PERIODIC: "periodic" },
        PlatformArch: { ARM: "arm", ARM64: "arm64", MIPS: "mips", MIPS64: "mips64", X86_32: "x86-32", X86_64: "x86-64" },
        PlatformNaclArch: { ARM: "arm", MIPS: "mips", MIPS64: "mips64", X86_32: "x86-32", X86_64: "x86-64" },
        PlatformOs: { ANDROID: "android", CROS: "cros", FUCHSIA: "fuchsia", LINUX: "linux", MAC: "mac", OPENBSD: "openbsd", WIN: "win" },
        RequestUpdateCheckStatus: { NO_UPDATE: "no_update", THROTTLED: "throttled", UPDATE_AVAILABLE: "update_available" },
        connect() { return { disconnect() {}, onDisconnect: { addListener() {} }, onMessage: { addListener() {} }, postMessage() {} }; },
        sendMessage() {},
        id: undefined,
      },
      csi() {
        const loadMs = performance.timeOrigin + Math.random() * 200 + 100;
        return { onloadT: Math.round(loadMs), pageT: Math.round(performance.now() * 1000), startE: Math.round(loadMs - performance.now()), tran: 15 };
      },
      loadTimes() {
        const loadSec = performance.timeOrigin / 1000 + Math.random() * 0.2 + 0.1;
        return { commitLoadTime: loadSec, connectionInfo: "h2", finishDocumentLoadTime: 0, finishLoadTime: 0, firstPaintAfterLoadTime: 0, firstPaintTime: 0, navigationType: "Other", npnNegotiatedProtocol: "h2", requestTime: loadSec - 0.5, startLoadTime: loadSec - 0.3, wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: true, wasNpnNegotiated: true };
      },
    };
  } else {
    try { delete globalThis.chrome; } catch (_) {}
  }

  // ---- CSS ----
  globalThis.CSS = globalThis.CSS || {
    supports(prop, value) {
      if (arguments.length === 1) return true;
      return true;
    },
    escape(str) { return String(str || ""); },
    highlights: new Map(),
  };

  // ---- IndexedDB ----
  globalThis.indexedDB = globalThis.indexedDB || {
    open() {
      const req = { onerror: null, onsuccess: null, onupgradeneeded: null, result: {}, error: null, readyState: "done" };
      setTimeout(() => { if (req.onsuccess) req.onsuccess({ target: req }); }, 0);
      return req;
    },
    deleteDatabase() { return { onerror: null, onsuccess: null, onupgradeneeded: null, result: undefined, readyState: "done" }; },
    cmp() { return 0; },
    databases() { return Promise.resolve([]); },
  };

  // ---- AudioContext（Web Audio API 指纹）----
  class AudioNodeStub {
    connect(dest) { return dest; }
    disconnect() {}
    addEventListener() {}
    removeEventListener() {}
  }

  class AudioContextBase {
    constructor() {
      this.state = "running";
      this.sampleRate = 44100;
      this.baseLatency = 0.005333;
      this.outputLatency = 0;
      this.currentTime = 0;
      this.destination = new AudioNodeStub();
      this.destination.maxChannelCount = 2;
      this.destination.channelCount = 2;
      this.destination.channelCountMode = "explicit";
      this.destination.channelInterpretation = "speakers";
      this.destination.numberOfInputs = 1;
      this.destination.numberOfOutputs = 0;
      this.listener = { positionX: { value: 0 }, positionY: { value: 0 }, positionZ: { value: 0 }, forwardX: { value: 0 }, forwardY: { value: 0 }, forwardZ: { value: -1 }, upX: { value: 0 }, upY: { value: 1 }, upZ: { value: 0 } };
      this.audioWorklet = { addModule() { return Promise.resolve(); } };
    }
    createOscillator() { const n = new AudioNodeStub(); n.type = "sine"; n.frequency = { value: 440, setValueAtTime() {} }; n.detune = { value: 0 }; n.start = () => {}; n.stop = () => {}; return n; }
    createGain() { const n = new AudioNodeStub(); n.gain = { value: 1, setValueAtTime() {}, linearRampToValueAtTime() {}, exponentialRampToValueAtTime() {} }; return n; }
    createBiquadFilter() { const n = new AudioNodeStub(); n.type = "lowpass"; n.frequency = { value: 350 }; n.detune = { value: 0 }; n.Q = { value: 1 }; n.gain = { value: 0 }; n.getFrequencyResponse = () => {}; return n; }
    createDynamicsCompressor() { const n = new AudioNodeStub(); n.threshold = { value: -24 }; n.knee = { value: 30 }; n.ratio = { value: 12 }; n.attack = { value: 0.003 }; n.release = { value: 0.25 }; n.reduction = 0; return n; }
    createAnalyser() { const n = new AudioNodeStub(); n.fftSize = 2048; n.frequencyBinCount = 1024; n.minDecibels = -100; n.maxDecibels = -30; n.smoothingTimeConstant = 0.8; n.getByteFrequencyData = (arr) => { if (arr) for (let i = 0; i < arr.length; i++) arr[i] = 0; }; n.getFloatFrequencyData = (arr) => { if (arr) for (let i = 0; i < arr.length; i++) arr[i] = -Infinity; }; n.getByteTimeDomainData = (arr) => { if (arr) for (let i = 0; i < arr.length; i++) arr[i] = 128; }; n.getFloatTimeDomainData = (arr) => { if (arr) for (let i = 0; i < arr.length; i++) arr[i] = 0; }; return n; }
    createBufferSource() { const n = new AudioNodeStub(); n.buffer = null; n.loop = false; n.loopStart = 0; n.loopEnd = 0; n.playbackRate = { value: 1 }; n.start = () => {}; n.stop = () => {}; n.onended = null; return n; }
    createBuffer(channels, length, sampleRate) { const data = new Float32Array(length || 1); return { numberOfChannels: channels || 1, length: length || 1, sampleRate: sampleRate || 44100, duration: (length || 1) / (sampleRate || 44100), getChannelData() { return data; }, copyFromChannel() {}, copyToChannel() {} }; }
    createScriptProcessor() { const n = new AudioNodeStub(); n.onaudioprocess = null; n.bufferSize = 4096; return n; }
    createChannelSplitter() { return new AudioNodeStub(); }
    createChannelMerger() { return new AudioNodeStub(); }
    createDelay() { const n = new AudioNodeStub(); n.delayTime = { value: 0 }; return n; }
    createConvolver() { const n = new AudioNodeStub(); n.buffer = null; n.normalize = true; return n; }
    createWaveShaper() { const n = new AudioNodeStub(); n.curve = null; n.oversample = "none"; return n; }
    createPanner() { return new AudioNodeStub(); }
    createStereoPanner() { const n = new AudioNodeStub(); n.pan = { value: 0 }; return n; }
    createMediaElementSource() { return new AudioNodeStub(); }
    createMediaStreamSource() { return new AudioNodeStub(); }
    createMediaStreamDestination() { const n = new AudioNodeStub(); n.stream = { getTracks() { return []; }, getAudioTracks() { return []; } }; return n; }
    createPeriodicWave() { return {}; }
    decodeAudioData(_buf, ok, err) { if (typeof err === "function") err(new Error("NotSupportedError")); return Promise.reject(new Error("NotSupportedError")); }
    resume() { this.state = "running"; return Promise.resolve(); }
    suspend() { this.state = "suspended"; return Promise.resolve(); }
    close() { this.state = "closed"; return Promise.resolve(); }
    addEventListener() {}
    removeEventListener() {}
  }

  globalThis.AudioContext = class AudioContext extends AudioContextBase {};
  globalThis.webkitAudioContext = globalThis.AudioContext;
  globalThis.OfflineAudioContext = class OfflineAudioContext extends AudioContextBase {
    constructor(channels, length, sampleRate) {
      super();
      this.length = length || 1;
      this.sampleRate = sampleRate || 44100;
    }
    startRendering() {
      const buf = this.createBuffer(1, this.length, this.sampleRate);
      const data = buf.getChannelData(0);
      const audioPrng = _seededPrng("offline-audio", `${this.length}:${this.sampleRate}`);
      const phase = audioPrng.next() * Math.PI * 2;
      const freq = 0.008 + audioPrng.next() * 0.006;
      const amp = 0.000008 + audioPrng.next() * 0.000004;
      for (let i = 0; i < data.length; i++) data[i] = Math.sin(i * freq + phase) * amp;
      return Promise.resolve(buf);
    }
  };

  // ---- Observer 类 ----
  globalThis.MutationObserver = globalThis.MutationObserver || class MutationObserver { constructor() {} observe() {} disconnect() {} takeRecords() { return []; } };
  globalThis.ResizeObserver = globalThis.ResizeObserver || class ResizeObserver { constructor() {} observe() {} unobserve() {} disconnect() {} };
  globalThis.IntersectionObserver = globalThis.IntersectionObserver || class IntersectionObserver { constructor() {} observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } };
  globalThis.PerformanceObserver = globalThis.PerformanceObserver || class PerformanceObserver { constructor() {} observe() {} disconnect() {} takeRecords() { return []; } };
  globalThis.ReportingObserver = class ReportingObserver { constructor() {} observe() {} disconnect() {} takeRecords() { return []; } };

  // ---- Image / Worker / SharedWorker / Notification ----
  globalThis.Image = class Image {
    constructor(w, h) { this.width = w || 0; this.height = h || 0; this.src = ""; this.onload = null; this.onerror = null; this.complete = false; this.naturalWidth = 0; this.naturalHeight = 0; }
  };
  globalThis.Worker = class Worker { constructor() {} postMessage() {} terminate() {} addEventListener() {} removeEventListener() {} };
  globalThis.SharedWorker = class SharedWorker { constructor() { this.port = { start() {}, close() {}, postMessage() {}, addEventListener() {}, removeEventListener() {} }; } };
  globalThis.Notification = class Notification { static get permission() { return "default"; } static requestPermission() { return Promise.resolve("default"); } constructor() {} };

  // ---- DOMParser ----
  globalThis.DOMParser = globalThis.DOMParser || class DOMParser {
    parseFromString(_str, _type) { return document; }
  };
  globalThis.XMLSerializer = globalThis.XMLSerializer || class XMLSerializer {
    serializeToString() { return ""; }
  };

  // ---- structuredClone ----
  globalThis.structuredClone = globalThis.structuredClone || ((obj) => JSON.parse(JSON.stringify(obj)));

  // ---- Blob / File (Node 18+ 已内置，仅 fallback) ----
  if (typeof globalThis.Blob === "undefined") {
    globalThis.Blob = class Blob {
      constructor(parts, options) { this.size = 0; this.type = (options && options.type) || ""; }
      text() { return Promise.resolve(""); }
      arrayBuffer() { return Promise.resolve(new ArrayBuffer(0)); }
      slice() { return new Blob(); }
    };
  }
  if (typeof globalThis.File === "undefined") {
    globalThis.File = class File extends globalThis.Blob {
      constructor(parts, name, options) { super(parts, options); this.name = name || ""; this.lastModified = Date.now(); }
    };
  }
  if (typeof globalThis.FileReader === "undefined") {
    globalThis.FileReader = class FileReader {
      constructor() { this.result = null; this.readyState = 0; this.error = null; this.onload = null; this.onerror = null; }
      readAsArrayBuffer() { this.readyState = 2; if (this.onload) this.onload({ target: this }); }
      readAsText() { this.readyState = 2; this.result = ""; if (this.onload) this.onload({ target: this }); }
      readAsDataURL() { this.readyState = 2; this.result = "data:;base64,"; if (this.onload) this.onload({ target: this }); }
      abort() {}
      addEventListener() {}
      removeEventListener() {}
    };
  }

  // ---- crypto ----
  const cryptoPrng = _makePrng(_mixSeed(runtimeState.seed_base, "crypto"));
  const randomFill = (arr) => {
    for (let i = 0; i < arr.length; i += 1) arr[i] = Math.floor(cryptoPrng.next() * 256);
    return arr;
  };
  globalThis.crypto = {
    subtle: (globalThis.crypto && globalThis.crypto.subtle) || undefined,
    randomUUID: () => {
        const h = "0123456789abcdef";
        let u = "";
        for (let i = 0; i < 36; i++) {
          if (i === 8 || i === 13 || i === 18 || i === 23) u += "-";
          else if (i === 14) u += "4";
          else if (i === 19) u += h[(cryptoPrng.next() * 4 | 0) + 8];
          else u += h[cryptoPrng.next() * 16 | 0];
        }
        return u;
      },
    getRandomValues: randomFill,
  };

  // ---- AbortController (Node 18+ 已内置) ----
  globalThis.AbortController = globalThis.AbortController || class AbortController {
    constructor() { this.signal = { aborted: false, reason: undefined, onabort: null, addEventListener() {}, removeEventListener() {}, throwIfAborted() {} }; }
    abort(reason) { this.signal.aborted = true; this.signal.reason = reason; }
  };

  const managedWindowPrefixes = [
    "_react", "__react", "__oai", "$R", "__STATSIG", "__REACT_INTL_CONTEXT__",
    "__SEGMENT_INSPECTOR__", "__sentinel", "DD_RUM", "dd_rum", "SentinelSDK",
  ];
  const routeWindowOwnKeys = new Set(routeProfile.windowOwnKeys || []);
  for (const key of Object.getOwnPropertyNames(globalThis)) {
    const managed = managedWindowPrefixes.some((prefix) => key.startsWith(prefix));
    if (!managed) continue;
    const shouldEnumerate = routeWindowOwnKeys.size ? routeWindowOwnKeys.has(key) : true;
    _setEnumerable(globalThis, key, shouldEnumerate);
  }

  // ---- 隐藏 Node.js 特征 ----
  // process 是最主要的 Node.js 检测信号
  // 注意：必须在设置 _nodeProcess 引用之后才能隐藏
  globalThis.process = undefined;
  try { delete globalThis.Buffer; } catch (_) {}
  try { delete globalThis.global; } catch (_) {}
  try { delete globalThis.setImmediate; } catch (_) {}
  try { delete globalThis.clearImmediate; } catch (_) {}

  // ---- 将浏览器 API 存根标记为不可枚举 ----
  // 真实 Chrome 中 Object.keys(window) 只返回 React/OAI 注入的属性，
  // 不包含 setTimeout/document/navigator 等原生 API（它们在 Window.prototype 上）。
  // Node.js 的 globalThis 赋值默认为可枚举，需手动修正。
  const _reactOaiPrefixes = [
    "_react", "__react", "__oai", "webpackChunk", "__webpack",
    "__STATSIG", "__DD_REAL", "__datadog", "dd_rum", "DD_RUM", "$R",
    "__REACT_INTL_CONTEXT__", "__SEGMENT_INSPECTOR__", "__NEXT",
    "__remixContext", "__remixRoute", "__remixManifest", "__sentinel",
  ];
  const _keepEnumerable = new Set([
    "undefined", "NaN", "Infinity",
  ]);
  for (const key of Object.getOwnPropertyNames(globalThis)) {
    if (_keepEnumerable.has(key) || routeWindowOwnKeys.has(key)) continue;
    if (!routeWindowOwnKeys.size && _reactOaiPrefixes.some(p => key.startsWith(p))) continue;
    const desc = Object.getOwnPropertyDescriptor(globalThis, key);
    if (desc && desc.enumerable && desc.configurable) {
      Object.defineProperty(globalThis, key, { ...desc, enumerable: false });
    }
  }

  const setDocumentSurface = (key, value) => {
    for (const currentKey of documentOwnKeys) _setEnumerable(document, currentKey, false);
    document[key] = value;
    _setEnumerable(document, key, true);
    documentOwnKeys.splice(0, documentOwnKeys.length, key);
    runtimeState.react_document_keys = documentOwnKeys.slice();
  };

  const setWindowSurface = (key, value) => {
    for (const currentKey of routeWindowOwnKeys) _setEnumerable(globalThis, currentKey, false);
    routeWindowOwnKeys.clear();
    routeWindowOwnKeys.add(key);
    if (!(key in globalThis)) globalThis[key] = value;
    _setEnumerable(globalThis, key, true);
  };

  const setNavigatorSurface = (key) => {
    const navigatorProto = Object.getPrototypeOf(navigator);
    for (const currentKey of Object.keys(navigatorProto)) {
      _setEnumerable(navigatorProto, currentKey, false);
    }
    _setEnumerable(navigatorProto, key, true);
    runtimeState.navigator_proto_own_keys = [key];
  };

  return {
    routeProfile,
    prepareEnforcement() {
      if (AUTH_ROUTE_NAMES.has(routeProfile.name)) {
        if (document.currentScript && _runtimePayload.enforcement_sdk_url) {
          document.currentScript.src = String(_runtimePayload.enforcement_sdk_url);
        }
        if (routeProfile.name === "oauth_create_account" && browserProfile === "safari") {
          setDocumentSurface(`__reactContainer$${_buildSuffix(runtimeState.prng)}`, {});
          setWindowSurface("DD_RUM", globalThis.DD_RUM || {});
        }
        return;
      }
      if (routeProfile.name === "chat_requirements") {
        setDocumentSurface(`__reactResources$${_buildSuffix(runtimeState.prng)}`, {});
        setWindowSurface("_g", {});
        setNavigatorSurface("maxTouchPoints");
      }
    },
    navigate(nextUrl) {
      const currentState = globalThis.history && globalThis.history.state || {};
      const currentIndex = Number(currentState.idx || 0);
      globalThis.history.pushState({ ...currentState, idx: currentIndex + 1 }, "", nextUrl);
      return this.exportState();
    },
    exportState() {
      currentPerfNow();
      if (performance.memory) {
        runtimeState.heap_total_js = performance.memory.totalJSHeapSize;
        runtimeState.heap_used_js = performance.memory.usedJSHeapSize;
      }
      runtimeState.history_state = _cloneJsonValue(globalThis.history && globalThis.history.state);
      runtimeState.react_document_keys = documentOwnKeys.slice();
      const gpuIdentity = _resolveGpuIdentity(_runtimePayload);
      return {
        seed_base: runtimeState.seed_base,
        rng_state: runtimeState.prng.getState(),
        time_origin: runtimeState.time_origin,
        perf_now: Number(_perfNow),
        wall_time_ms: runtimeState.wall_time_ms,
        heap_total_js: runtimeState.heap_total_js,
        heap_used_js: runtimeState.heap_used_js,
        history_state: runtimeState.history_state,
        history_length: Number(globalThis.history && globalThis.history.length || 0),
        location_href: String(globalThis.location && globalThis.location.href || ""),
        local_storage_keys: Object.keys(globalThis.localStorage || {}),
        react_document_keys: runtimeState.react_document_keys,
        navigator_proto_own_keys: runtimeState.navigator_proto_own_keys.slice(),
        navigator_exposed_keys: Object.getOwnPropertyNames(Object.getPrototypeOf(navigator)),
        route_profile_name: routeProfile.name,
        browser_profile: browserProfile,
        timezone: requestedTimezone,
        has_performance_memory: "memory" in performance,
        navigator_platform: navigator.platform,
        navigator_vendor: navigator.vendor,
        has_user_agent_data: "userAgentData" in navigator,
        has_chrome: "chrome" in globalThis,
        plugin_names: Array.from(navigator.plugins || []).map(plugin => plugin.name),
        webgl_vendor: gpuIdentity.vendor,
        webgl_renderer: gpuIdentity.renderer,
        document_domain: document.domain,
        window_origin: globalThis.origin,
        script_urls: scripts.map((scriptEl) => scriptEl.src),
      };
    },
    dispose() {
      for (const handle of _pendingTimers.values()) {
        if (typeof _realClearTimeout === "function") _realClearTimeout(handle);
      }
      _pendingTimers.clear();
    },
  };
}

function loadPatchedSdk(sdkSource) {
  let sdk = String(sdkSource || "");
  let matchedSdkProfile = false;
  for (const p of PATCHES) {
    if (p.applies && !p.applies(sdk)) continue;
    if (p.applies) matchedSdkProfile = true;
    const patched = sdk.replace(p.find, p.replace);
    if (patched === sdk) {
      throw solverError("SDK_PATCH_FAILED", `Sentinel SDK patch did not match: ${p.name}`);
    }
    sdk = patched;
  }
  if (!matchedSdkProfile) {
    throw solverError("SDK_PATCH_FAILED", "Sentinel SDK structure is unsupported");
  }
  sdk = sdk.replaceAll('"(((.+)+)+)+$"', '".+"');
  eval(sdk);
}

function solverError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function createSolverContext(payload, sdkSource) {
  _nodeProcess.stderr.write(`[solver] installRuntime...\n`);
  const runtime = installRuntime(payload);
  const hostUrl = _resolveHostPageUrl(payload);
  const flow = String(payload.flow || payload.action || "");
  _nodeProcess.stderr.write(`[solver] routeProfile=${runtime.routeProfile.name} path=${hostUrl}\n`);
  _nodeProcess.stderr.write(`[solver] loadPatchedSdk...\n`);
  loadPatchedSdk(sdkSource);
  _setEnumerable(globalThis, "__debugP", false);
  _setEnumerable(globalThis, "SentinelSDK", (runtime.routeProfile.windowOwnKeys || []).includes("SentinelSDK"));

  const P = globalThis.__debugP;
  _nodeProcess.stderr.write(`[solver] P exists=${!!P} action=${payload.action}\n`);
  if (!P) throw solverError("SDK_INIT_FAILED", "Sentinel SDK did not expose its client");
  if (P && typeof P.getConfig === "function" && !P.__debugWrappedGetConfig) {
    const originalGetConfig = P.getConfig.bind(P);
    P.getConfig = (...args) => {
      const result = originalGetConfig(...args);
      const logConfig = (config) => {
        _nodeProcess.stderr.write(
          `[solver] getConfig OK, [0]=${config[0]} [10]=${String(config[10]).slice(0, 32)} [11]=${String(config[11]).slice(0, 48)} [12]=${String(config[12]).slice(0, 48)} [13]=${config[13]}\n`
        );
        return config;
      };
      if (result && typeof result.then === "function") {
        return result.then(logConfig);
      }
      return logConfig(result);
    };
    P.__debugWrappedGetConfig = true;
  }

  return {
    basePayload: { ...payload },
    flow,
    P,
    runtime,
    phase: "new",
    exchangeCount: 0,
    exchangeKind: "",
    prefetchCount: 0,
    requestP: "",
    sid: "",
  };
}

function validateRequirementsProof(requestP) {
  const proof = String(requestP || "").trim();
  if (!proof) throw solverError("MISSING_REQUEST_PROOF", "requirements proof is empty");
  if (proof.startsWith(`gAAAAAC${SDK_PROOF_ERROR_PREFIX}`)) {
    throw solverError("SDK_PROOF_FAILED", "Sentinel requirements proof contains an SDK error");
  }
  return proof;
}

async function runRequirements(context) {
  const repeatedPlatformExchange = context.flow === "update_organization" && context.phase === "solved";
  if (context.phase !== "new" && !repeatedPlatformExchange) {
    throw solverError("INVALID_PHASE", `requirements is not valid in phase ${context.phase}`);
  }
  const requestP = validateRequirementsProof(await context.P.getRequirementsToken());
  const sid = context.P.sid || "";
  context.requestP = requestP;
  context.sid = sid;
  context.exchangeKind = "requirements";
  context.phase = "requirements_done";
  return { request_p: requestP, sid, runtime_state: context.runtime.exportState() };
}

async function runChatRequirements(context) {
  if (context.phase !== "new") {
    throw solverError("INVALID_PHASE", `chat requirements is not valid in phase ${context.phase}`);
  }
  if (typeof context.P.getRequirementsTokenBlocking !== "function") {
    throw solverError("SDK_PROOF_FAILED", "blocking requirements proof is unavailable");
  }
  const requestP = validateRequirementsProof(context.P.getRequirementsTokenBlocking());
  const sid = context.P.sid || "";
  context.requestP = requestP;
  context.sid = sid;
  context.exchangeKind = "chat_requirements";
  context.phase = "requirements_done";
  return { request_p: requestP, sid, runtime_state: context.runtime.exportState() };
}

async function runPrefetchRequirements(context) {
  if (context.flow !== "oauth_create_account" || context.phase !== "solved") {
    throw solverError("INVALID_PHASE", `prefetch requirements is not valid in phase ${context.phase}`);
  }
  if (context.prefetchCount > 0) {
    throw solverError("INVALID_PHASE", "prefetch requirements already completed");
  }
  const requestP = validateRequirementsProof(await context.P.getRequirementsToken());
  const sid = context.P.sid || context.sid || "";
  context.prefetchCount += 1;
  return { request_p: requestP, sid, runtime_state: context.runtime.exportState() };
}

function runTransitionFlow(context, payload) {
  if (context.phase !== "solved") {
    throw solverError("INVALID_PHASE", `flow transition is not valid in phase ${context.phase}`);
  }
  const nextFlow = String(payload.flow || "").trim();
  const nextHostPageUrl = String(payload.host_page_url || "").trim();
  if (!nextFlow || !nextHostPageUrl) {
    throw solverError("INVALID_TRANSITION", "flow transition requires flow and host_page_url");
  }
  context.runtime.navigate(nextHostPageUrl);
  context.flow = nextFlow;
  context.basePayload = {
    ...context.basePayload,
    ...payload,
    flow: nextFlow,
    host_page_url: nextHostPageUrl,
  };
  context.exchangeKind = "transition_flow";
  context.phase = "requirements_done";
  return {
    request_p: context.requestP,
    sid: context.sid,
    runtime_state: context.runtime.exportState(),
  };
}

async function runSolve(context, payload) {
  if (context.phase !== "requirements_done") {
    throw solverError("INVALID_PHASE", `solve is not valid in phase ${context.phase}`);
  }
  const challenge = payload.challenge || {};
  const requestP = String(context.requestP || "").trim();
  if (!requestP) throw solverError("MISSING_REQUEST_PROOF", "missing request_p");
  if (payload.request_p && String(payload.request_p) !== requestP) {
    throw solverError("CONTEXT_MISMATCH", "request proof changed within solver session");
  }
  if (payload.sid && context.sid && String(payload.sid) !== String(context.sid)) {
    throw solverError("CONTEXT_MISMATCH", "sid changed within solver session");
  }
  if (context.sid) context.P.sid = context.sid;
  context.runtime.prepareEnforcement();
  const sdk = globalThis.SentinelSDK;
  if (!sdk || typeof sdk.__debug_bindProof !== "function") {
    throw solverError("SDK_BINDING_MISSING", "Sentinel SDK proof binding is unavailable");
  }
  sdk.__debug_bindProof(challenge, requestP);
  const { flow, P } = context;
  const soRequired = challenge && challenge.so && challenge.so.required === true;
  if (typeof sdk.__debug_bindSO === "function") {
    try {
      sdk.__debug_bindSO(flow, challenge);
    } catch (soBindErr) {
      if (soRequired) {
        throw solverError("REQUIRED_SO_FAILED", `session observer binding failed: ${soBindErr && soBindErr.message || soBindErr}`);
      }
      _nodeProcess.stderr.write(`[solver] bindSO error: ${soBindErr && soBindErr.message || soBindErr}\n`);
    }
  } else if (soRequired) {
    throw solverError("REQUIRED_SO_FAILED", "session observer binding is unavailable");
  }
  const finalP = await P.getEnforcementToken(challenge);
  if (String(finalP || "").startsWith(`gAAAAAB${SDK_PROOF_ERROR_PREFIX}`)) {
    throw solverError("SDK_PROOF_FAILED", "Sentinel final proof contains an SDK error");
  }
  const turnstile = challenge && challenge.turnstile || {};
  const turnstileRequired = turnstile.required === true;
  const dx = turnstile.dx;
  let tValue = null;
  if (dx) {
    if (typeof sdk.__debug_n !== "function") {
      if (turnstileRequired) {
        throw solverError("REQUIRED_TURNSTILE_FAILED", "turnstile solver is unavailable");
      }
      _nodeProcess.stderr.write("[solver] turnstile solver is unavailable\n");
    } else {
      try {
        tValue = await sdk.__debug_n(challenge, dx);
        _nodeProcess.stderr.write(`[solver] turnstile t length=${tValue ? tValue.length : 0}\n`);
      } catch (tErr) {
        if (turnstileRequired) {
          throw solverError("REQUIRED_TURNSTILE_FAILED", `turnstile solve failed: ${tErr && tErr.message || tErr}`);
        }
        _nodeProcess.stderr.write(`[solver] turnstile error: ${tErr && tErr.message || tErr}\n`);
      }
    }
  } else {
    if (turnstileRequired) {
      throw solverError("REQUIRED_TURNSTILE_FAILED", "required turnstile dx is missing");
    }
    _nodeProcess.stderr.write("[solver] no turnstile dx in challenge\n");
  }
  if (turnstileRequired && (typeof tValue !== "string" || !tValue.trim())) {
    throw solverError("REQUIRED_TURNSTILE_FAILED", "required turnstile result is empty");
  }
  if (turnstileRequired && isEncodedSolverFailure(tValue)) {
    throw solverError("REQUIRED_TURNSTILE_FAILED", "required turnstile result contains an SDK execution error");
  }
  const cValue = String(challenge.token || "").trim();
  if (typeof sdk.__debug_wrap !== "function") {
    throw solverError("SDK_WRAPPER_MISSING", "Sentinel SDK token wrapper is unavailable");
  }
  const tokenJson = sdk.__debug_wrap({ p: finalP, t: tValue, c: cValue }, flow);
  if (typeof tokenJson !== "string" || !tokenJson.trim()) {
    throw solverError("SDK_WRAPPER_FAILED", "Sentinel SDK token wrapper returned an empty result");
  }
  const behavior = await simulateHumanBehavior(payload.behavior_duration_ms, flow, {
    otp: payload.behavior_otp,
    name: payload.behavior_name,
    age: payload.behavior_age,
  });
  let sessionObserverToken = "";
  if (typeof sdk.sessionObserverToken === "function") {
    try {
      sessionObserverToken = await sdk.sessionObserverToken(flow) || "";
      _nodeProcess.stderr.write(
        `[solver] sessionObserverToken length=${sessionObserverToken ? sessionObserverToken.length : 0}\n`
      );
    } catch (soErr) {
      if (soRequired) {
        throw solverError("REQUIRED_SO_FAILED", `session observer solve failed: ${soErr && soErr.message || soErr}`);
      }
      _nodeProcess.stderr.write(`[solver] sessionObserverToken error: ${soErr && soErr.message || soErr}\n`);
    }
  } else if (soRequired) {
    throw solverError("REQUIRED_SO_FAILED", "session observer solver is unavailable");
  }
  if (soRequired && (typeof sessionObserverToken !== "string" || !sessionObserverToken.trim())) {
    throw solverError("REQUIRED_SO_FAILED", "required session observer result is empty");
  }
  if (soRequired && isSessionObserverFailure(sessionObserverToken)) {
    throw solverError("REQUIRED_SO_FAILED", "required session observer result contains an SDK execution error");
  }
  context.phase = "solved";
  context.exchangeCount += 1;
  return {
    final_p: finalP,
    t: tValue,
    c: cValue,
    token_json: tokenJson,
    session_observer_token: sessionObserverToken,
    behavior_duration_ms: behavior.durationMs,
    behavior_event_count: behavior.eventCount,
    runtime_state: context.runtime.exportState(),
  };
}

async function run(payload, sdkSource) {
  const context = createSolverContext(payload, sdkSource);
  try {
    if (payload.action === "requirements") return await runRequirements(context);
    if (payload.action === "chat_requirements") return await runChatRequirements(context);
    if (payload.action === "solve") {
      context.requestP = String(payload.request_p || "").trim();
      context.sid = String(payload.sid || "");
      context.phase = "requirements_done";
      return await runSolve(context, payload);
    }
    if (payload.action === "prefetch_requirements") {
      throw solverError("INVALID_PHASE", "prefetch requirements requires a persistent solver session");
    }
    if (payload.action === "transition_flow") {
      throw solverError("INVALID_PHASE", "flow transition requires a persistent solver session");
    }
    throw solverError("UNSUPPORTED_ACTION", `unsupported action: ${payload.action}`);
  } finally {
    context.runtime.dispose();
  }
}

// ========== Node.js 入口 ==========
// 先保存 Node.js 原生引用（installRuntime 会隐藏 process）
const fs = require("fs");
const _nodeProcess = process;
const _realSetTimeout = setTimeout;
const _realClearTimeout = clearTimeout;
const _RealDate = Date;
const _RealIntlDateTimeFormat = Intl.DateTimeFormat;
const _NodeBuffer = Buffer;
const MAX_SERVER_LINE_BYTES = 5 * 1024 * 1024;
const SDK_PROOF_ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D";

function readSdkSource() {
  const sdkFile = _nodeProcess.env.SENTINEL_SDK_FILE;
  if (!sdkFile) throw solverError("MISSING_SDK_FILE", "SENTINEL_SDK_FILE env not set");
  return fs.readFileSync(sdkFile, "utf8");
}

async function runOneShot() {
  let input = "";
  _nodeProcess.stdin.setEncoding("utf8");
  _nodeProcess.stdin.on("data", (chunk) => { input += chunk; });
  _nodeProcess.stdin.on("end", async () => {
    try {
      const payload = JSON.parse(input || "{}");
      const result = await run(payload, readSdkSource());
      _nodeProcess.stdout.write(JSON.stringify(result));
    } catch (err) {
      _nodeProcess.stderr.write(err && err.stack ? String(err.stack) : String(err));
      _nodeProcess.exitCode = 1;
    }
  });
}

function writeServerResponse(response) {
  return new Promise((resolve, reject) => {
    const line = `${JSON.stringify(response)}\n`;
    _nodeProcess.stdout.write(line, (error) => error ? reject(error) : resolve());
  });
}

async function runServer() {
  const sdkSource = readSdkSource();
  let context = null;
  let buffer = "";
  let queue = Promise.resolve();
  let shuttingDown = false;

  const disposeContext = () => {
    if (context) context.runtime.dispose();
    context = null;
  };

  const handleMessage = async (message) => {
    const id = message && message.id != null ? message.id : null;
    const action = String(message && message.action || "");
    const payload = message && message.payload && typeof message.payload === "object"
      ? message.payload
      : {};
    try {
      let result;
      if (action === "requirements") {
        if (!context) {
          context = createSolverContext({ ...payload, action }, sdkSource);
        } else {
          if (context.flow !== "update_organization" || context.phase !== "solved") {
            throw solverError("INVALID_PHASE", "requirements already started");
          }
          if (payload.flow && String(payload.flow) !== context.flow) {
            throw solverError("CONTEXT_MISMATCH", "flow changed within solver session");
          }
          if (payload.device_id && String(payload.device_id) !== String(context.basePayload.device_id || "")) {
            throw solverError("CONTEXT_MISMATCH", "device_id changed within solver session");
          }
          const nextHostPageUrl = String(payload.host_page_url || "").trim();
          if (!nextHostPageUrl) {
            throw solverError("MISSING_PAGE_URL", "repeated requirements requires host_page_url");
          }
          context.runtime.navigate(nextHostPageUrl);
          context.basePayload.host_page_url = nextHostPageUrl;
        }
        result = await runRequirements(context);
      } else if (action === "chat_requirements") {
        if (context) throw solverError("INVALID_PHASE", "chat requirements requires a fresh solver session");
        context = createSolverContext({
          ...payload,
          action,
          flow: "chat_requirements",
          host_page_url: payload.host_page_url || FLOW_HOST_PAGE_URLS.chat_requirements,
        }, sdkSource);
        result = await runChatRequirements(context);
      } else if (action === "solve") {
        if (!context) throw solverError("INVALID_PHASE", "solve requires requirements first");
        result = await runSolve(context, payload);
      } else if (action === "prefetch_requirements") {
        if (!context) throw solverError("INVALID_PHASE", "prefetch requirements requires solve first");
        result = await runPrefetchRequirements(context);
      } else if (action === "transition_flow") {
        if (!context) throw solverError("INVALID_PHASE", "flow transition requires solve first");
        result = runTransitionFlow(context, payload);
      } else if (action === "shutdown") {
        shuttingDown = true;
        disposeContext();
        await writeServerResponse({ id, ok: true, result: null });
        _nodeProcess.stdin.pause();
        _nodeProcess.exit(0);
        return;
      } else {
        throw solverError("UNSUPPORTED_ACTION", `unsupported action: ${action}`);
      }
      await writeServerResponse({ id, ok: true, result });
    } catch (err) {
      await writeServerResponse({
        id,
        ok: false,
        error: {
          code: String(err && err.code || "SOLVER_ERROR"),
          message: String(err && err.message || err),
        },
      });
    }
  };

  const enqueueLine = (line) => {
    if (!line.trim() || shuttingDown) return;
    queue = queue.then(async () => {
      let message;
      try {
        message = JSON.parse(line);
      } catch (_) {
        await writeServerResponse({
          id: null,
          ok: false,
          error: { code: "INVALID_JSON", message: "invalid protocol JSON" },
        });
        return;
      }
      await handleMessage(message);
    });
  };

  _nodeProcess.stdin.setEncoding("utf8");
  _nodeProcess.stdin.on("data", (chunk) => {
    buffer += chunk;
    if (_NodeBuffer.byteLength(buffer, "utf8") > MAX_SERVER_LINE_BYTES) {
      disposeContext();
      _nodeProcess.stderr.write("solver protocol line exceeded 5 MiB\n");
      _nodeProcess.exit(1);
      return;
    }
    let newlineIndex;
    while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newlineIndex);
      buffer = buffer.slice(newlineIndex + 1);
      enqueueLine(line);
    }
  });
  _nodeProcess.stdin.on("end", () => {
    if (buffer.trim()) enqueueLine(buffer);
    queue.finally(() => {
      if (!shuttingDown) disposeContext();
    });
  });
}

if (require.main === module) {
  if (_nodeProcess.argv.includes("--server")) {
    runServer().catch((err) => {
      _nodeProcess.stderr.write(err && err.stack ? String(err.stack) : String(err));
      _nodeProcess.exit(1);
    });
  } else {
    runOneShot().catch((err) => {
      _nodeProcess.stderr.write(err && err.stack ? String(err.stack) : String(err));
      _nodeProcess.exit(1);
    });
  }
}

module.exports = {
  _behaviorModifierFields,
  _resolveBehaviorSequence,
  _resolvePasteShortcut,
};
