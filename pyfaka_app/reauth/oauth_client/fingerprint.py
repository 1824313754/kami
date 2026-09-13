"""Anything Analyzer 风格的桌面 Chrome 指纹生成器。

每次注册只选择一次平台/GPU 预设，并在该预设内随机屏幕、DPR、CPU、
内存和渲染器。返回值同时供 HTTP Client Hints 与 Sentinel 页面运行时使用，
避免跨平台字段被独立随机后互相冲突。
"""
from __future__ import annotations

import datetime
import os
import random


_CHROME_VERSIONS = (
    "131.0.0.0",
    "130.0.0.0",
    "129.0.0.0",
    "128.0.0.0",
    "127.0.0.0",
)

_WINDOWS_PRESETS = (
    {
        "platform": "Win32",
        "oscpu": "Windows NT 10.0; Win64; x64",
        "screens": ((1920, 1080), (2560, 1440), (1366, 768), (1536, 864)),
        "dprs": (1, 1.25, 1.5),
        "webgl_vendors": ("Google Inc. (NVIDIA)",),
        "webgl_renderers": (
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
        "hardware_concurrencies": (4, 8, 12, 16),
        "device_memories": (8, 16, 32),
        "color_depth": 24,
    },
    {
        "platform": "Win32",
        "oscpu": "Windows NT 10.0; Win64; x64",
        "screens": ((1920, 1080), (2560, 1440)),
        "dprs": (1, 1.25),
        "webgl_vendors": ("Google Inc. (Intel)",),
        "webgl_renderers": (
            "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
        "hardware_concurrencies": (4, 8, 12),
        "device_memories": (8, 16),
        "color_depth": 24,
    },
    {
        "platform": "Win32",
        "oscpu": "Windows NT 10.0; Win64; x64",
        "screens": ((1920, 1080), (2560, 1440), (3440, 1440)),
        "dprs": (1, 1.25, 1.5),
        "webgl_vendors": ("Google Inc. (AMD)",),
        "webgl_renderers": (
            "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
            "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        ),
        "hardware_concurrencies": (8, 12, 16),
        "device_memories": (16, 32),
        "color_depth": 24,
    },
)

_MACOS_PRESETS = (
    {
        "platform": "MacIntel",
        "oscpu": "Intel Mac OS X 10_15_7",
        "screens": ((1440, 900), (1680, 1050), (2560, 1600)),
        "dprs": (2,),
        "webgl_vendors": ("Google Inc. (Apple)",),
        "webgl_renderers": (
            "ANGLE (Apple, Apple M1, OpenGL 4.1)",
            "ANGLE (Apple, Apple M2, OpenGL 4.1)",
            "ANGLE (Apple, Apple M3, OpenGL 4.1)",
        ),
        "hardware_concurrencies": (8, 10, 12),
        "device_memories": (8, 16),
        "color_depth": 30,
    },
    {
        "platform": "MacIntel",
        "oscpu": "Intel Mac OS X 10_15_7",
        "screens": ((1440, 900), (1680, 1050)),
        "dprs": (2,),
        "webgl_vendors": ("Google Inc. (Intel)",),
        "webgl_renderers": (
            "ANGLE (Intel, Intel(R) Iris Plus Graphics 645, OpenGL 4.1)",
            "ANGLE (Intel, Intel(R) Iris Plus Graphics, OpenGL 4.1)",
        ),
        "hardware_concurrencies": (4, 8),
        "device_memories": (8, 16),
        "color_depth": 24,
    },
)

_LINUX_PRESETS = (
    {
        "platform": "Linux x86_64",
        "oscpu": "Linux x86_64",
        "screens": ((1920, 1080), (2560, 1440)),
        "dprs": (1,),
        "webgl_vendors": ("Google Inc. (NVIDIA)",),
        "webgl_renderers": (
            "ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Ti, OpenGL 4.5)",
            "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070, OpenGL 4.5)",
        ),
        "hardware_concurrencies": (8, 12, 16),
        "device_memories": (16, 32),
        "color_depth": 24,
    },
    {
        "platform": "Linux x86_64",
        "oscpu": "Linux x86_64",
        "screens": ((1920, 1080),),
        "dprs": (1,),
        "webgl_vendors": ("Google Inc. (Intel)",),
        "webgl_renderers": (
            "ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.5)",
        ),
        "hardware_concurrencies": (4, 8),
        "device_memories": (8, 16),
        "color_depth": 24,
    },
)

_ALL_PRESETS = _WINDOWS_PRESETS + _MACOS_PRESETS + _LINUX_PRESETS

_TIMEZONE_LANGUAGES = {
    "Asia/Shanghai": ("zh-CN", "zh", "en"),
    "Asia/Tokyo": ("ja", "en"),
    "Asia/Seoul": ("ko", "en"),
    "America/New_York": ("en-US", "en"),
    "America/Los_Angeles": ("en-US", "en"),
    "America/Chicago": ("en-US", "en"),
    "Europe/London": ("en-GB", "en"),
    "Europe/Berlin": ("de-DE", "de", "en"),
    "Europe/Paris": ("fr-FR", "fr", "en"),
    "Europe/Moscow": ("ru-RU", "ru", "en"),
    "Asia/Singapore": ("en-SG", "zh", "en"),
    "Asia/Hong_Kong": ("zh-HK", "zh", "en"),
    "Asia/Taipei": ("zh-TW", "zh", "en"),
}

_TIMEZONE_OFFSETS = {
    "Asia/Shanghai": -480,
    "Asia/Tokyo": -540,
    "Asia/Seoul": -540,
    "America/New_York": 300,
    "America/Los_Angeles": 480,
    "America/Chicago": 360,
    "Europe/London": 0,
    "Europe/Berlin": -60,
    "Europe/Paris": -60,
    "Europe/Moscow": -180,
    "Asia/Singapore": -480,
    "Asia/Hong_Kong": -480,
    "Asia/Taipei": -480,
}

_WINDOWS_TIMEZONE_ALIASES = {
    "China Standard Time": "Asia/Shanghai",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "Eastern Standard Time": "America/New_York",
    "Pacific Standard Time": "America/Los_Angeles",
    "Central Standard Time": "America/Chicago",
    "GMT Standard Time": "Europe/London",
    "W. Europe Standard Time": "Europe/Berlin",
    "Russian Standard Time": "Europe/Moscow",
    "Singapore Standard Time": "Asia/Singapore",
    "Taipei Standard Time": "Asia/Taipei",
    "中国标准时间": "Asia/Shanghai",
}


def _system_timezone() -> str:
    configured = str(os.environ.get("TZ") or "").strip()
    if configured:
        return configured
    tzinfo = datetime.datetime.now().astimezone().tzinfo
    key = str(getattr(tzinfo, "key", "") or "").strip()
    if key:
        return key
    name = str(tzinfo or "").strip()
    return _WINDOWS_TIMEZONE_ALIASES.get(name, name or "Asia/Shanghai")


def _accept_language(languages: tuple[str, ...]) -> str:
    return ",".join(
        language if index == 0 else f"{language};q={1 - index * 0.1:.1f}"
        for index, language in enumerate(languages)
    )


def _current_timezone_offset() -> int:
    offset = datetime.datetime.now().astimezone().utcoffset()
    return -int((offset.total_seconds() if offset else 0) // 60)


def generate_fingerprint(
    rng: random.Random | None = None,
    *,
    timezone: str = "",
) -> dict:
    """生成一套在平台预设内部自洽的桌面 Chrome 指纹。"""
    r = rng or random.SystemRandom()
    preset = r.choice(_ALL_PRESETS)
    chrome_version = r.choice(_CHROME_VERSIONS)
    chrome_major = chrome_version.split(".", 1)[0]
    screen_width, screen_height = r.choice(preset["screens"])
    device_pixel_ratio = r.choice(preset["dprs"])
    hardware_concurrency = r.choice(preset["hardware_concurrencies"])
    memory_options = tuple(
        memory
        for memory in preset["device_memories"]
        if memory >= hardware_concurrency
    )
    device_memory = r.choice(memory_options or preset["device_memories"])
    timezone_name = str(timezone or "").strip() or _system_timezone()
    languages = _TIMEZONE_LANGUAGES.get(timezone_name, ("en-US", "en"))
    gpu_vendor = r.choice(preset["webgl_vendors"])
    gpu_renderer = r.choice(preset["webgl_renderers"])
    canvas_noise = r.randrange(0xFFFFFFFF)
    audio_noise = r.randrange(0xFFFFFFFF)

    if preset["platform"] == "MacIntel":
        user_agent_platform = "Macintosh; Intel Mac OS X 10_15_7"
        sec_ch_platform = '"macOS"'
    elif preset["platform"] == "Linux x86_64":
        user_agent_platform = "X11; Linux x86_64"
        sec_ch_platform = '"Linux"'
    else:
        user_agent_platform = "Windows NT 10.0; Win64; x64"
        sec_ch_platform = '"Windows"'

    user_agent = (
        f"Mozilla/5.0 ({user_agent_platform}) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36"
    )
    sec_ch_ua = (
        f'"Chromium";v="{chrome_major}", '
        f'"Google Chrome";v="{chrome_major}", '
        '"Not-A.Brand";v="8"'
    )

    return {
        "browser_profile": "chrome",
        "impersonate": "chrome131",
        "user_agent": user_agent,
        "sec_ch_ua": sec_ch_ua,
        "sec_ch_ua_platform": sec_ch_platform,
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_full_version": f'"{chrome_version}"',
        "sec_ch_ua_full_version_list": (
            f'"Chromium";v="{chrome_version}", '
            f'"Google Chrome";v="{chrome_version}", '
            '"Not-A.Brand";v="8.0.0.0"'
        ),
        "platform": preset["platform"],
        "oscpu": preset["oscpu"],
        "app_version": user_agent.replace("Mozilla/", "", 1),
        "screen": f"{screen_width}x{screen_height}",
        "screen_width": screen_width,
        "screen_height": screen_height,
        "lang": languages[0],
        "lang_full": _accept_language(languages),
        "languages": list(languages),
        "hardware_concurrency": hardware_concurrency,
        "device_memory": device_memory,
        "navigator_platform": preset["platform"],
        "navigator_vendor": "Google Inc.",
        "max_touch_points": 0,
        "gpu_vendor": gpu_vendor,
        "gpu_renderer": gpu_renderer,
        "device_pixel_ratio": device_pixel_ratio,
        "color_depth": preset["color_depth"],
        "canvas_noise": canvas_noise,
        "audio_noise": audio_noise,
        "fingerprint_seed": (canvas_noise << 32) | audio_noise,
        "timezone": timezone_name,
        "timezone_offset": _TIMEZONE_OFFSETS.get(
            timezone_name,
            _current_timezone_offset(),
        ),
        "webrtc_policy": "block",
        "is_mac": preset["platform"] == "MacIntel",
    }
