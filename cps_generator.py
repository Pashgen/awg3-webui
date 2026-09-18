"""
AmneziaWG 2.0 CPS Generator — Python port of generator.ts
Ported from: https://github.com/Vadim-Khristenko/AmneziaWG-Architect
"""

import random
import os
import re
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Types / constants
# ─────────────────────────────────────────────────────────────────────────────

MIMIC_PROFILES = [
    "quic_initial", "quic_0rtt", "tls_client_hello", "wireguard_noise",
    "dtls", "http3", "sip", "tls_to_quic", "quic_burst", "dns_query", "random"
]

BROWSER_PROFILES = ["chrome", "edge", "firefox", "safari", "yandex_desktop", "yandex_mobile", ""]

CHROMIUM_PROFILES = {"chrome", "edge", "yandex_desktop", "yandex_mobile"}

PROFILE_LABELS = {
    "quic_initial": "QUIC Initial",
    "quic_0rtt": "QUIC 0-RTT",
    "tls_client_hello": "TLS 1.3",
    "wireguard_noise": "Noise_IK",
    "dtls": "DTLS 1.3",
    "http3": "HTTP/3",
    "sip": "SIP",
    "tls_to_quic": "TLS → QUIC",
    "quic_burst": "QUIC Burst",
    "dns_query": "DNS Query",
    "random": "Random",
}

# ─────────────────────────────────────────────────────────────────────────────
# Host pools
# ─────────────────────────────────────────────────────────────────────────────

HOST_POOLS = {
    "quic_initial": [
        "yandex.net", "yastatic.net", "s3.yandex.net", "storage.yandexcloud.net",
        "cloud.yandex.ru", "dzen.ru", "music.yandex.ru", "vk.com", "mycdn.me",
        "vk-cdn.net", "userapi.com", "ok.ru", "mail.ru", "imgsmail.ru", "cdn.mail.ru",
        "avito.ru", "ozon.ru", "cdn1.ozone.ru", "wildberries.ru", "wbstatic.net",
        "kinopoisk.ru", "ivi.ru", "rutube.ru", "rt.ru", "sber.ru", "sberbank.ru",
        "sbp.ru", "tbank.ru", "raiffeisen.ru", "vtb.ru", "alfabank.ru",
        "gazprombank.ru", "sovcombank.ru", "rosbank.ru", "kaspersky.ru", "kaspersky.com",
        "drweb.ru", "selectel.ru", "selectel.com", "timeweb.cloud", "timeweb.com",
        "reg.ru", "beget.com", "mchost.ru", "nic.ru", "dataline.ru", "mts.ru",
        "beeline.ru", "megafon.ru", "rostelecom.ru", "tele2.ru", "mvideo.ru",
        "eldorado.ru", "dns-shop.ru", "citilink.ru", "lamoda.ru", "sportmaster.ru",
        "detmir.ru", "sbermegamarket.ru", "gosuslugi.ru", "mos.ru", "nalog.ru",
        "pfr.gov.ru", "cbr.ru", "roscosmos.ru", "premier.one", "okko.tv", "more.tv",
        "1tv.ru", "ntv.ru", "russia.tv", "rbc.ru", "tass.ru", "ria.ru", "gazeta.ru",
        "lenta.ru", "hh.ru", "superjob.ru", "2gis.ru", "championat.com", "sports.ru",
        "rambler.ru", "livejournal.com",
        "gcore.com", "api.gcore.com", "cdn.gcore.com", "g.gcdn.co", "gcdn.co",
        "bunny.net", "b-cdn.net", "storage.bunnycdn.com", "cdn77.com", "rsc.cdn77.org",
        "fastly.net", "a.ssl.fastly.net", "global.fastly.net", "fastlylabs.com",
        "a248.e.akamai.net", "akamaiedge.net", "akamaihd.net", "akamaistream.net",
        "edgekey.net", "akam.net", "cloudfront.net", "d1.awsstatic.com", "d2.awsstatic.com",
        "s3.amazonaws.com", "msedge.net", "cdn.office.net", "azureedge.net",
        "azure.microsoft.com", "live.com", "outlook.com", "office.com", "hotmail.com",
        "microsoft.com", "xbox.com", "xboxlive.com", "onedrive.live.com",
        "trafficmanager.net", "icloud.com", "cdn-apple.com", "mzstatic.com",
        "apple.com", "appleid.apple.com", "limelight.com", "llnwd.net", "edg.io",
        "highwinds.com", "stackpathdns.com", "cachefly.net", "imperva.com",
        "github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
        "codeload.github.com", "github.githubassets.com", "cdn.jsdelivr.net", "unpkg.com",
        "registry.npmjs.org", "pypi.org", "archive.ubuntu.com", "steamstatic.com",
        "steamcontent.com", "steampowered.com", "epicgames.com", "ea.com", "battle.net",
        "blizzard.com", "ubisoft.com", "riotgames.com", "spotify.com", "scdn.co",
        "heads-ak.spotify.com", "jtvnw.net", "wikipedia.org", "upload.wikimedia.org",
        "wikimedia.org", "hetzner.com", "hetzner.de", "ovhcloud.com", "ovh.net",
        "digitalocean.com", "dropbox.com", "notion.so", "zoom.us", "linode.com",
        "tencentcs.com", "tencent.com", "myqcloud.com", "alicdn.com", "aliyuncs.com",
        "alibabacloud.com", "huaweicloud.com", "hwcdn.net", "baidu.com", "bdstatic.com",
        "bceloss.com",
    ],

    "quic_0rtt": [
        "yandex.net", "yastatic.net", "storage.yandexcloud.net", "vk.com", "mycdn.me",
        "vk-cdn.net", "mail.ru", "ozon.ru", "avito.ru", "wildberries.ru", "wbstatic.net",
        "kinopoisk.ru", "sber.ru", "kaspersky.com", "selectel.ru", "timeweb.cloud",
        "tbank.ru", "alfabank.ru", "gosuslugi.ru",
        "gcore.com", "cdn.gcore.com", "g.gcdn.co", "gcdn.co", "bunny.net", "b-cdn.net",
        "cdn77.com", "fastly.net", "a.ssl.fastly.net", "global.fastly.net",
        "cloudfront.net", "s3.amazonaws.com", "d1.awsstatic.com",
        "msedge.net", "cdn.office.net", "live.com", "office.com", "xbox.com",
        "icloud.com", "cdn-apple.com", "mzstatic.com", "akamaiedge.net",
        "akamaihd.net", "edgekey.net",
        "github.com", "objects.githubusercontent.com", "cdn.jsdelivr.net",
        "unpkg.com", "registry.npmjs.org", "archive.ubuntu.com",
        "steamstatic.com", "steamcontent.com", "spotify.com", "scdn.co",
        "wikipedia.org", "wikimedia.org", "dropbox.com", "epicgames.com",
        "alicdn.com", "tencentcs.com", "myqcloud.com", "huaweicloud.com", "bdstatic.com",
    ],

    "tls_client_hello": [
        "yandex.net", "yandex.ru", "yastatic.net", "s3.yandex.net",
        "storage.yandexcloud.net", "cloud.yandex.ru", "dzen.ru", "music.yandex.ru",
        "vk.com", "mycdn.me", "vk-cdn.net", "userapi.com", "ok.ru", "mail.ru",
        "imgsmail.ru", "cdn.mail.ru", "avito.ru", "ozon.ru", "cdn1.ozone.ru",
        "wildberries.ru", "wbstatic.net", "kinopoisk.ru", "ivi.ru", "rutube.ru",
        "premier.one", "okko.tv", "more.tv", "rt.ru", "russia.tv", "1tv.ru", "ntv.ru",
        "ren.tv", "tvc.ru", "5-tv.ru",
        "sber.ru", "sberbank.ru", "sbp.ru", "online.sberbank.ru", "tbank.ru",
        "raiffeisen.ru", "vtb.ru", "vtb24.ru", "alfabank.ru", "gazprombank.ru",
        "sovcombank.ru", "rosbank.ru", "otkritie.ru", "rshb.ru", "pochtabank.ru",
        "bspb.ru", "kaspersky.ru", "kaspersky.com", "drweb.ru", "drweb.com",
        "roscosmos.ru", "gosuslugi.ru", "mos.ru", "nalog.ru", "pfr.gov.ru", "cbr.ru",
        "esia.gosuslugi.ru", "epgu.gosuslugi.ru",
        "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru", "rostelecom.ru",
        "selectel.ru", "selectel.com", "timeweb.cloud", "timeweb.com", "reg.ru",
        "beget.com", "nic.ru", "dataline.ru", "mchost.ru", "spaceweb.ru", "sweb.ru",
        "ihc.ru", "fastvps.ru",
        "citilink.ru", "mvideo.ru", "sbermegamarket.ru", "lamoda.ru", "eldorado.ru",
        "detmir.ru", "sportmaster.ru", "letoile.ru", "dns-shop.ru", "technopark.ru",
        "nix.ru", "aliexpress.ru", "joom.com",
        "gazeta.ru", "rbc.ru", "kommersant.ru", "tass.ru", "ria.ru", "hh.ru",
        "superjob.ru", "rabota.ru", "rambler.ru", "lenta.ru", "rg.ru", "kp.ru",
        "mk.ru", "izvestia.ru", "iz.ru", "vedomosti.ru", "2gis.ru", "maps.yandex.ru",
        "championat.com", "sports.ru", "matchtv.ru", "livejournal.com", "pikabu.ru",
        "habr.com", "vc.ru", "spark.ru", "ruvds.com", "vdsina.ru", "gcorelabs.com",
        "gcore.com", "api.gcore.com", "cdn.gcore.com", "g.gcdn.co", "gcdn.co",
        "bunny.net", "b-cdn.net", "storage.bunnycdn.com", "cdn77.com", "rsc.cdn77.org",
        "fastly.net", "a.ssl.fastly.net", "global.fastly.net", "fastlylabs.com",
        "a248.e.akamai.net", "akam.net", "akamaiedge.net", "akamaihd.net",
        "akamaistream.net", "edgekey.net",
        "cloudfront.net", "d1.awsstatic.com", "d2.awsstatic.com", "s3.amazonaws.com",
        "aws.amazon.com", "msedge.net", "azure.microsoft.com", "azureedge.net",
        "cdn.office.net", "live.com", "outlook.com", "hotmail.com", "office.com",
        "onedrive.live.com", "xbox.com", "xboxlive.com", "microsoft.com",
        "trafficmanager.net", "icloud.com", "cdn-apple.com", "mzstatic.com",
        "apple.com", "appleid.apple.com", "limelight.com", "llnwd.net", "edg.io",
        "stackpathdns.com", "cachefly.net", "imperva.com", "incapsula.com", "sucuri.net",
        "github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
        "codeload.github.com", "github.githubassets.com", "avatars.githubusercontent.com",
        "releases.githubusercontent.com", "gitlab.com", "bitbucket.org",
        "cdn.jsdelivr.net", "unpkg.com", "registry.npmjs.org", "pypi.org",
        "files.pythonhosted.org", "archive.ubuntu.com", "security.ubuntu.com",
        "packages.ubuntu.com", "deb.debian.org", "ftp.debian.org", "launchpad.net",
        "snapcraft.io", "alpinelinux.org", "archlinux.org", "centos.org", "fedoraproject.org",
        "steamstatic.com", "steamcontent.com", "steampowered.com", "steamcdn-a.akamaihd.net",
        "store.steampowered.com", "epicgames.com", "ea.com", "ubisoft.com",
        "battle.net", "blizzard.com", "riotgames.com", "leagueoflegends.com",
        "spotify.com", "scdn.co", "heads-ak.spotify.com", "jtvnw.net", "twitchsvc.net",
        "wikipedia.org", "upload.wikimedia.org", "wikimedia.org", "wikidata.org",
        "commons.wikimedia.org", "hetzner.com", "hetzner.de", "hetzner.cloud",
        "your-server.de", "ovhcloud.com", "ovh.net", "ovh.com", "gra-g1.ovh.net",
        "digitalocean.com", "do.co", "linode.com", "vultr.com",
        "dropbox.com", "dropboxstatic.com", "dropboxapi.com", "notion.so",
        "notionusercontent.com", "zoom.us", "zmtr.cn", "docker.com", "hub.docker.com",
        "registry-1.docker.io", "quay.io", "ghcr.io", "jetbrains.com",
        "plugins.jetbrains.com", "download.jetbrains.com",
        "tencentcs.com", "tencent.com", "myqcloud.com", "qpic.cn", "alicdn.com",
        "aliyuncs.com", "alibabacloud.com", "huaweicloud.com", "hwcdn.net",
        "baidu.com", "bdstatic.com", "bceloss.com",
    ],

    "dtls": [
        "turn.yandex.net", "stun.yandex.net", "stun1.yandex.net", "telemost.yandex.ru",
        "turn.vk.com", "stun.vk.com", "stun1.vk.com", "rtc.vk.com",
        "stun.mail.ru", "turn.mail.ru", "stun.sipnet.ru", "stun.sipnet.net",
        "stun.zadarma.com", "turn.zadarma.com", "stun.zepter.ru", "stun.mango-office.ru",
        "stun.beeline.ru", "stun.mts.ru", "stun.megafon.ru", "stun.rostelecom.ru",
        "stun.tele2.ru", "stun.sber.ru",
        "stun.stunprotocol.org", "stunserver.stunprotocol.org",
        "stun.voip.ipp2p.com", "stun.voipstunt.com", "stun.voipbuster.com",
        "stun.voipwise.com", "stun.voiptia.net", "stun.voxox.com", "stun.voxgratia.org",
        "stun.voys.nl", "stun.voztele.com", "stun.voipzoom.com", "stun.vopium.com",
        "stun.ippi.fr", "stun.antisip.com", "stun.freecall.com", "stun.internetcalls.com",
        "stun.counterpath.com", "stun.counterpath.net", "stun.softjoys.com",
        "stun.sipgate.net", "stun.sip.us", "stun.ekiga.net", "stun.ideasip.com",
        "stun.schlund.de", "stun.xs4all.nl", "stun.xten.com", "stun.sonetel.com",
        "stun.sonetel.net", "stun.rock.com", "stun.ooma.com", "stun.vyke.com",
        "stun.webcalldirect.com", "stun.wwdl.net", "stun.yesdates.com",
        "stun.yesss.at", "stun.zoiper.com", "stun01.sipphone.com",
        "stun1.faktortel.com.au", "stun.noc.ams-ix.net", "stun.xtratelecom.es",
        "stun.wifirst.net", "stun.whoi.edu", "stun.zadv.com", "stun.zentauron.de",
        "stun.voztovoice.org", "stun1.voiceeclipse.net", "stun.f.haeder.net",
        "meet.jit.si", "stun.jit.si", "turn.jit.si", "8x8.vc",
        "stun.services.mozilla.com", "turn.matrix.org", "stun.matrix.org",
        "stun.nextcloud.com", "turn.nextcloud.com", "janus.conf.meetecho.com",
        "stun.meetecho.com",
        "global.stun.twilio.com", "stun.us1.twilio.com", "stun.ie1.twilio.com",
        "stun.au1.twilio.com", "stun.us2.twilio.com", "stun.nexmo.com",
        "stun.vonage.com", "global.stun.bandwidth.com", "stun.plivo.com",
        "stun.signalwire.com", "stun.livekit.cloud", "stun.metered.ca",
        "openrelay.metered.ca", "coturn.net", "freestun.net",
        "relay.webwormhole.io", "expressturn.com",
    ],

    "sip": [
        "sip.beeline.ru", "voip.beeline.ru", "sip.mts.ru", "voip.mts.ru",
        "sip.megafon.ru", "voip.megafon.ru", "sip.tele2.ru", "voip.tele2.ru",
        "sip.rostelecom.ru", "voip.rostelecom.ru", "sip.mtt.ru", "voip.mtt.ru",
        "sip.vk.com", "sip.yandex.ru", "sip.mail.ru", "voip.sberbank.ru",
        "sip.vats.sber.ru", "sip.tbank.ru", "sip.sipnet.ru", "sip.sipnet.net",
        "sip2.sipnet.ru", "sip.mango-office.ru", "pbx.mango-office.ru",
        "sip.zadarma.com", "pbx.zadarma.com", "sip.gravitel.ru", "sip.onlinepbx.ru",
        "sip.uis.ru", "pbx.uis.ru", "sip.comagic.ru", "sip.binotel.ru",
        "sip.novofon.ru", "sip.megacall.ru", "sip.zebra-telecom.ru",
        "sip.obit.ru", "sip.mtsglobaltelecom.ru", "pbx.rt.ru", "sip.telfin.ru",
        "sip.uiscom.ru", "sip.voxlink.ru", "sip.datafox.ru", "sip.sipmarket.net",
        "sip.ngs.ru", "sip.kolabora.com", "sip.sipuni.com", "sip.voximplant.com",
        "sip.exolve.ru", "sip.dialpad.ru", "sip.oblako.ru", "pbx.onlinesim.ru",
        "sip.onlinesim.ru", "sip.iptel.org",
        "sip2sip.info", "sip.linphone.org", "proxy.sipthor.net", "sip.sipthor.net",
        "sip.antisip.com", "sip.ippi.fr", "sip.voipbuster.com", "sip.voipstunt.com",
        "sip.freecall.com", "sip.powervoip.com", "sip.poivy.com", "sip.voipwise.com",
        "sip.internetcalls.com", "sip.counterpath.com", "sipml5.org", "sip.zoiper.com",
        "sip.microsip.org", "asterisk.org", "sip.asterisk.org", "sip.kamailio.org",
        "sip.opensips.org", "sip.freeswitch.org",
        "sip.vonage.com", "sip.ringcentral.com", "sip.8x8.com", "sip.plivo.com",
        "sip.telnyx.com", "sip.bandwidth.com", "sip.twilio.com",
        "global.sip.twilio.com", "sip.infobip.com", "sip.messagebird.com",
        "sip.signalwire.com", "sip.did.telnyx.com", "sip.livekit.cloud",
        "sip.dialpad.com", "sip.aircall.io", "sip.3cx.com",
    ],

    "dns_query": [
        "77.88.8.8", "77.88.8.1", "77.88.8.88", "77.88.8.2", "77.88.8.7", "77.88.8.3",
        "62.76.76.62", "62.76.62.76", "195.46.39.39", "195.46.39.40",
        "138.124.81.6", "77.91.68.8", "92.223.109.31", "185.64.91.189",
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2",
        "1.1.1.3", "1.0.0.3", "9.9.9.9", "149.112.112.112", "9.9.9.10",
        "149.112.112.10", "208.67.222.222", "208.67.220.220", "208.67.222.123",
        "208.67.220.123", "94.140.14.14", "94.140.15.15", "94.140.14.140",
        "94.140.14.141", "94.140.14.15", "94.140.15.16", "8.26.56.26", "8.20.247.20",
        "185.228.168.9", "185.228.169.9", "185.228.168.10", "185.228.169.11",
        "185.228.168.168", "185.228.169.168", "64.6.64.6", "64.6.65.6",
        "156.154.70.1", "156.154.71.1", "4.2.2.1", "4.2.2.2", "4.2.2.3",
        "4.2.2.4", "4.2.2.5", "4.2.2.6", "199.85.126.10", "199.85.127.10",
        "76.76.19.19", "76.223.122.150", "208.76.50.50", "208.76.51.51",
        "87.118.111.215", "213.187.11.62", "81.218.119.11", "209.88.198.133",
        "84.200.69.80", "84.200.70.40", "74.82.42.42", "216.146.35.35",
        "216.146.36.36", "74.118.212.1", "74.118.212.2",
        "223.5.5.5", "223.6.6.6", "119.29.29.29", "182.254.116.116",
        "114.114.114.114", "114.114.115.115", "101.101.101.101", "101.102.103.104",
        "103.2.57.5", "103.2.57.6", "101.226.4.6", "218.30.118.6",
        "193.17.47.1", "185.43.135.1", "130.59.31.248", "130.59.31.251",
        "185.95.218.42", "185.95.218.43", "158.64.1.29",
        "149.112.121.10", "149.112.122.10",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# BFP — Browser Fingerprint Profiles
# slot → [min_bytes, max_bytes]
# ─────────────────────────────────────────────────────────────────────────────

BFP = {
    "chrome":        {"qi": (1250,1250), "q0": (1250,1350), "h3": (1250,1350), "tls": (512,800),  "nx": (1200,1250), "dtls": (1100,1200)},
    "edge":          {"qi": (1250,1250), "q0": (1250,1350), "h3": (1250,1350), "tls": (512,800),  "nx": (1200,1250), "dtls": (1100,1200)},
    "firefox":       {"qi": (1200,1252), "q0": (1200,1300), "h3": (1200,1350), "tls": (512,700),  "nx": (1200,1250), "dtls": (1050,1200)},
    "safari":        {"qi": (1250,1252), "q0": (1250,1300), "h3": (1250,1350), "tls": (512,750),  "nx": (1200,1250), "dtls": (1100,1200)},
    "yandex_desktop":{"qi": (1250,1250), "q0": (1250,1350), "h3": (1350,1350), "tls": (512,800),  "nx": (1200,1250), "dtls": (1100,1200)},
    "yandex_mobile": {"qi": (1232,1232), "q0": (1250,1350), "h3": (1350,1350), "tls": (512,800),  "nx": (1200,1250), "dtls": (1100,1200)},
}

# ─────────────────────────────────────────────────────────────────────────────
# Utility functions
# ─────────────────────────────────────────────────────────────────────────────

def rnd(a: int, b: int) -> int:
    """Random integer in [a, b] inclusive."""
    return random.randint(a, b)


def rh(n: int) -> str:
    """n random bytes as lowercase hex string."""
    return os.urandom(n).hex()


def hex_pad(value: int, byte_len: int) -> str:
    """Number → fixed-length hex (big-endian), byte_len bytes."""
    return format(value & ((1 << (byte_len * 8)) - 1), f'0{byte_len * 2}x')


def assert_even_hex(hex_str: str, label: str = "") -> str:
    """Ensure hex string has even length."""
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Odd hex length in {label}: {len(hex_str)}")
    return hex_str


def r_range(base: int, spread: int = 500_000) -> str:
    """Returns 'start-end' string for H1-H4 ranges."""
    start = max(0, base - rnd(0, spread))
    end = start + rnd(spread // 2, spread)
    return f"{start}-{end}"


def split_pad(n: int, tag: str = "r") -> str:
    """Splits large padding into CPS tags ≤1000 each."""
    if n <= 0:
        return ""
    parts = []
    remaining = n
    while remaining > 1000:
        parts.append(f"<{tag} 1000>")
        remaining -= 1000
    if remaining > 0:
        parts.append(f"<{tag} {remaining}>")
    return "".join(parts)


def tag_overhead(use_t: bool) -> int:
    """4 bytes per <t> tag."""
    # TODO: <c> tag (packet counter, 4 bytes) — раскомментировать когда клиенты AWG добавят поддержку:
    #   def tag_overhead(use_c: bool, use_t: bool) -> int:
    #       return (4 if use_c else 0) + (4 if use_t else 0)
    return 4 if use_t else 0


def align_to_128(n: int) -> int:
    """Align to next multiple of 128 bytes (TLS ClientHello padding)."""
    return ((n + 127) // 128) * 128


def calc_padding(header_b: int, extra_b: int, fp_range: Optional[tuple], iv: int, mtu: int) -> int:
    """Calculate padding to fill to target size."""
    if fp_range is None:
        return max(0, min(rnd(10, 40) * iv, 200, mtu - header_b - extra_b))
    target = rnd(fp_range[0], fp_range[1])
    pad = target - header_b - extra_b
    # Clamp to [0, mtu - header_b - extra_b]
    return max(0, min(pad, mtu - header_b - extra_b))


def get_host(inp: dict, pool_key: str) -> str:
    """Pick a host from custom or pool."""
    custom = inp.get("custom_host", "").strip()
    if custom:
        return custom
    pool = HOST_POOLS.get(pool_key, HOST_POOLS["quic_initial"])
    return pool[rnd(0, len(pool) - 1)]


def get_fp_range(inp: dict, slot: str) -> Optional[tuple]:
    """Get BFP range for a slot, or None if browser profile not set."""
    if not inp.get("use_browser_fp") or not inp.get("browser_profile"):
        return None
    profile = inp.get("browser_profile", "")
    table = BFP.get(profile)
    if not table:
        return None
    return table.get(slot)


# ─────────────────────────────────────────────────────────────────────────────
# Protocol generators
# ─────────────────────────────────────────────────────────────────────────────

def mk_quic_i(inp: dict, iv: int) -> str:
    """QUIC Initial (Long Header 0xC0–0xC3, UDP 443)."""
    host = get_host(inp, "quic_initial")
    dcid = rnd(8, 20)
    scid = rnd(0, 20)
    token_len = 0 if rnd(0, 1) == 0 else rnd(8, 32)
    sni_rc = min(len(host) + rnd(0, 6), 64)

    hex_str = assert_even_hex(
        hex_pad(0xc0 | rnd(0, 3), 1) +  # 1B flags
        "00000001" +                      # 4B version=1
        hex_pad(dcid, 1) +               # 1B DCID length
        rh(dcid) +                        # N DCID
        hex_pad(scid, 1) +               # 1B SCID length
        rh(scid) +                        # M SCID
        hex_pad(token_len, 1) +          # 1B token length
        rh(token_len) +                   # K token
        rh(4),                            # 4B reserved
        "mk_quic_i"
    )

    mtu = inp.get("mtu", 1280)
    header_b = len(hex_str) // 2
    extra_b = (sni_rc if inp.get("use_tag_rc") else 0) + tag_overhead(inp.get("use_tag_t", False))
    pad = calc_padding(header_b, extra_b, get_fp_range(inp, "qi"), iv, mtu)

    return (
        f"<b 0x{hex_str}>" +
        (f"<rc {sni_rc}>" if inp.get("use_tag_rc") else "") +
        ("<t>" if inp.get("use_tag_t") else "") +
        (split_pad(pad) if inp.get("use_tag_r") else "")
    )


def mk_quic_0(inp: dict, iv: int) -> str:
    """QUIC 0-RTT Early Data (Long Header 0xD0–0xD3)."""
    host = get_host(inp, "quic_0rtt")
    dcid = rnd(8, 20)
    scid = rnd(0, 20)
    ticket_hint = min(len(host) + rnd(4, 16), 48)

    hex_str = assert_even_hex(
        hex_pad(0xd0 | rnd(0, 3), 1) +
        "00000001" +
        hex_pad(dcid, 1) +
        rh(dcid) +
        hex_pad(scid, 1) +
        rh(scid) +
        rh(4),
        "mk_quic_0"
    )

    mtu = inp.get("mtu", 1280)
    header_b = len(hex_str) // 2
    extra_b = (ticket_hint if inp.get("use_tag_rc") else 0) + tag_overhead(inp.get("use_tag_t", False))
    pad = calc_padding(header_b, extra_b, get_fp_range(inp, "q0"), iv, mtu)

    return (
        f"<b 0x{hex_str}>" +
        ("<t>" if inp.get("use_tag_t") else "") +
        (split_pad(pad) if inp.get("use_tag_r") else "") +
        (f"<rc {ticket_hint}>" if inp.get("use_tag_rc") else "")
    )


def mk_tls(inp: dict, iv: int) -> str:
    """TLS 1.3 Client Hello."""
    host = get_host(inp, "tls_client_hello")
    sni_ext = 2 + 2 + 2 + 1 + 2 + len(host)
    sni_rc = min(sni_ext, 64)

    fp_range = get_fp_range(inp, "tls")
    base_len = rnd(fp_range[0], fp_range[1]) if fp_range else rnd(300, 550)
    browser_profile = inp.get("browser_profile", "")
    rec_len = align_to_128(base_len) if browser_profile in CHROMIUM_PROFILES else base_len
    hs_len = rec_len - rnd(4, 9)

    mtu = inp.get("mtu", 1280)
    r_len = min(
        rnd(20, 60) * iv,
        300,
        max(0, mtu - 44 - sni_rc - tag_overhead(inp.get("use_tag_t", False)))
    )

    hex_str = assert_even_hex(
        "160301" +              # content_type + legacy_version
        hex_pad(rec_len, 2) +  # record length
        "01" +                  # ClientHello
        hex_pad(hs_len, 3) +   # handshake length
        "0303" +                # TLS 1.2 legacy
        rh(32),                 # client random
        "mk_tls"
    )

    return (
        f"<b 0x{hex_str}>" +
        (f"<rc {sni_rc}>" if inp.get("use_tag_rc") else "") +
        (split_pad(r_len) if inp.get("use_tag_r") else "") +
        ("<t>" if inp.get("use_tag_t") else "")
    )


def mk_noise(inp: dict, iv: int) -> str:
    """WireGuard Noise_IK Handshake Initiation (148 bytes)."""
    rc_len = rnd(4, 12)
    header_b = 148  # Noise_IK strictly 148 bytes

    mtu = inp.get("mtu", 1280)
    extra_b = (rc_len if inp.get("use_tag_rc") else 0) + tag_overhead(inp.get("use_tag_t", False))
    fp_range = get_fp_range(inp, "nx")
    if fp_range:
        pad = calc_padding(header_b, extra_b, fp_range, iv, mtu)
    else:
        pad = min(rnd(10, 40) * iv, 200, max(0, mtu - header_b - extra_b))

    return (
        f"<b 0x01000000{rh(4)}>" +  # 4B type=1 + 3B reserved + 4B sender_index
        f"<b 0x{rh(32)}>" +           # 32B ephemeral public key
        f"<b 0x{rh(48)}>" +           # 48B encrypted static
        f"<b 0x{rh(28)}>" +           # 28B encrypted timestamp
        f"<b 0x{rh(32)}>" +           # 32B MAC1 + MAC2
        (split_pad(pad) if inp.get("use_tag_r") else "") +
        ("<t>" if inp.get("use_tag_t") else "") +
        (f"<rc {rc_len}>" if inp.get("use_tag_rc") else "")
    )


def mk_dtls(inp: dict, iv: int) -> str:
    """DTLS 1.2 Client Hello (WebRTC)."""
    host = get_host(inp, "dtls")
    frag_len = rnd(100, 300)
    sni_rc = min(len(host) + rnd(2, 8), 60)
    epoch = rnd(0, 255)

    hex_str = assert_even_hex(
        "16" +                     # content_type = Handshake
        "fefd" +                   # DTLS 1.2
        hex_pad(epoch, 2) +        # epoch
        rh(6) +                    # sequence number
        hex_pad(frag_len, 2) +     # fragment length
        "01" +                     # ClientHello
        rh(6) +                    # 3B hs_len + 2B msg_seq + 1B pad
        "fefd0000" +               # dtls_version + cookie_len=0
        rh(4) +                    # random prefix
        rh(32),                    # random
        "mk_dtls"
    )

    mtu = inp.get("mtu", 1280)
    header_b = len(hex_str) // 2
    extra_b = (sni_rc if inp.get("use_tag_rc") else 0) + tag_overhead(inp.get("use_tag_t", False))
    pad = calc_padding(header_b, extra_b, get_fp_range(inp, "dtls"), iv, mtu)

    return (
        f"<b 0x{hex_str}>" +
        (f"<rc {sni_rc}>" if inp.get("use_tag_rc") else "") +
        ("<t>" if inp.get("use_tag_t") else "") +
        (split_pad(pad) if inp.get("use_tag_r") else "")
    )


def mk_http3(inp: dict, iv: int) -> str:
    """HTTP/3 Host Mimicry (QUIC Long Header, extended types)."""
    host = get_host(inp, "quic_initial")
    ptypes = [0xc0, 0xc1, 0xc2, 0xc3, 0xe0, 0xe1, 0xe2]
    dcid = rnd(8, 20)
    scid = rnd(0, 20)
    sni_len = min(len(host) + 9 + rnd(0, 6), 64)

    hex_str = assert_even_hex(
        hex_pad(ptypes[rnd(0, len(ptypes) - 1)], 1) +
        "00000001" +
        hex_pad(dcid, 1) +
        rh(dcid) +
        hex_pad(scid, 1) +
        rh(scid) +
        rh(4),
        "mk_http3"
    )

    mtu = inp.get("mtu", 1280)
    header_b = len(hex_str) // 2
    extra_b = (sni_len if inp.get("use_tag_rc") else 0) + tag_overhead(inp.get("use_tag_t", False))
    pad = calc_padding(header_b, extra_b, get_fp_range(inp, "h3"), iv, mtu)

    return (
        f"<b 0x{hex_str}>" +
        (f"<rc {sni_len}>" if inp.get("use_tag_rc") else "") +
        (split_pad(pad) if inp.get("use_tag_r") else "") +
        ("<t>" if inp.get("use_tag_t") else "")
    )


def mk_sip(inp: dict, iv: int) -> str:
    """SIP REGISTER request mimicry."""
    host = get_host(inp, "sip")
    host_hex = "".join(format(ord(c), "02x") for c in host)

    hex_str = assert_even_hex(
        "524547495354455220736970" +  # "REGISTER sip"
        "3a" +                         # ":"
        host_hex +                     # host as ASCII hex
        "20" +                         # SP
        rh(4),                         # random suffix
        "mk_sip"
    )

    mtu = inp.get("mtu", 1280)
    header_b = len(hex_str) // 2
    rc_val = min(len(host) + rnd(8, 24) * iv, 150)
    r_len = min(
        rnd(5, 30) * iv,
        120,
        max(0, mtu - header_b - rc_val - tag_overhead(inp.get("use_tag_t", False)))
    )

    return (
        f"<b 0x{hex_str}>" +
        (f"<rc {rc_val}>" if inp.get("use_tag_rc") else "") +
        ("<t>" if inp.get("use_tag_t") else "") +
        (split_pad(r_len) if inp.get("use_tag_r") else "")
    )


def mk_dns(inp: dict, iv: int) -> str:
    """DNS query mimicry."""
    host = get_host(inp, "dns_query")

    # Encode domain in DNS label format
    query_name_hex = ""
    for label in host.split("."):
        len_hex = format(len(label), "02x")
        label_hex = "".join(format(ord(c), "02x") for c in label)
        query_name_hex += len_hex + label_hex
    query_name_hex += "00"

    txid = rh(2)
    flags = "0100"
    qdcount = "0001"
    ancount = "0000"
    nscount = "0000"
    arcount = "0000"
    qtype = "0001" if iv % 2 == 0 else "001c"  # A or AAAA
    qclass = "0001"

    dns_hex = txid + flags + qdcount + ancount + nscount + arcount + query_name_hex + qtype + qclass
    hex_str = assert_even_hex(dns_hex, "mk_dns")

    mtu = inp.get("mtu", 1280)
    header_b = len(hex_str) // 2
    target_size = rnd(64, min(512, mtu - 20))
    r_len = max(0, target_size - header_b)

    return (
        f"<b 0x{hex_str}>" +
        (split_pad(min(r_len, 200)) if inp.get("use_tag_r") and r_len > 0 else "") +
        ("<t>" if inp.get("use_tag_t") else "")
    )


def mk_entropy(inp: dict, idx: int, iv: int) -> str:
    """Entropy packets for I2–I5."""
    mtu = inp.get("mtu", 1280)
    is_big = rnd(1, 10) > 6
    base_len = rnd(200, 500) if is_big else rnd(4, 20)
    r_len = min(
        base_len * iv,
        500 if is_big else 60,
        max(0, mtu - 20 - tag_overhead(inp.get("use_tag_t", False)))
    )

    rc_len = rnd(4, 12)
    rd_len = rnd(4, 8)

    c = ""
    t = "<t>" if inp.get("use_tag_t") else ""
    r = split_pad(r_len) if inp.get("use_tag_r") else ""
    rc = f"<rc {rc_len}>" if inp.get("use_tag_rc") else ""
    rd = f"<rd {rd_len}>" if inp.get("use_tag_rd") else ""
    b = f"<b 0x{rh(rnd(4, 8 * iv))}>" if iv >= 2 else ""
    b2 = f"<b 0x{rh(rnd(2, 4))}>" if iv >= 3 else ""

    patterns = [
        b + r + t + rc + c + rd,
        c + t + b + r + rc + rd,
        rc + b + r + c + t + rd,
        t + r + c + rc + b + rd,
        r + rc + b + t + c + rd,
        b2 + t + r + b + rc + c + rd,
        rd + b + rc + r + t + c + b2,
        c + b + b2 + t + rc + r + rd,
    ]

    result = patterns[(idx + rnd(0, len(patterns) - 1)) % len(patterns)]
    return result or "<r 10>"


# ─────────────────────────────────────────────────────────────────────────────
# Entry points
# ─────────────────────────────────────────────────────────────────────────────

def gen_i1(inp: dict, profile: str, iv: int) -> str:
    """Select and call the right generator based on mimic profile."""
    dispatch = {
        "quic_initial":    mk_quic_i,
        "quic_0rtt":       mk_quic_0,
        "tls_client_hello": mk_tls,
        "wireguard_noise": mk_noise,
        "dtls":            mk_dtls,
        "http3":           mk_http3,
        "sip":             mk_sip,
        "dns_query":       mk_dns,
        "tls_to_quic":     mk_tls,   # I1 = TLS
        "quic_burst":      mk_quic_i,  # I1 = QUIC Initial
    }

    if profile == "random":
        keys = list(dispatch.keys())
        return gen_i1(inp, keys[rnd(0, len(keys) - 1)], iv)

    fn = dispatch.get(profile, mk_quic_i)
    return fn(inp, iv)


def gen_cfg(inp: dict) -> dict:
    """
    Generate a full AWG configuration.

    inp keys:
      version: "1.0" | "1.5" | "2.0" | "3.1"  (3.1 uses identical CPS output to 2.0;
                                    the extra 3.1-only fields are generated separately
                                    by gen_awg31_extra())
      intensity: "low" | "medium" | "high"
      profile: mimic profile string
      iter_count: int (auto-boost on failure)
      junk_level: int
      use_extreme_max: bool
      router_mode: bool
      mimic_all: bool
      use_tag_t: bool
      use_tag_r: bool
      use_tag_rc: bool
      use_tag_rd: bool
      use_browser_fp: bool
      browser_profile: str
      mtu: int
      custom_host: str
    """
    version = inp.get("version", "2.0")
    intensity = inp.get("intensity", "medium")
    profile = inp.get("profile", "quic_initial")
    iter_count = inp.get("iter_count", 0)
    junk_level = inp.get("junk_level", 4)
    use_extreme_max = inp.get("use_extreme_max", False)
    router_mode = inp.get("router_mode", False)

    imap = {"low": 1, "medium": 2, "high": 3}
    iv = imap.get(intensity, 2) + (1 if iter_count > 3 else 0)

    # ── H1–H4 ranges ──
    h1_spread = 10_000_000 if use_extreme_max else 100_000_000
    h2_spread = 10_000_000 if use_extreme_max else 100_000_000
    h3_spread = 10_000_000 if use_extreme_max else 100_000_000
    h4_spread = 15_000_000 if use_extreme_max else 150_000_000

    h1 = r_range(rnd(100_000_000, 900_000_000), h1_spread)
    h2 = r_range(rnd(1_200_000_000, 2_000_000_000), h2_spread)
    h3 = r_range(rnd(2_400_000_000, 3_200_000_000), h3_spread)
    h4 = r_range(rnd(3_600_000_000, 4_000_000_000), h4_spread)

    # ── H1s–H4s single values (AWG 1.x) ──
    h1s_spread = 10_000_000 if use_extreme_max else 4_000_000
    h1s = 100_000_000 + rnd(0, h1s_spread)
    h2s = 1_200_000_000 + rnd(0, h2_spread)
    h3s = 2_400_000_000 + rnd(0, h3_spread)
    h4s = 3_600_000_000 + rnd(0, h4_spread)

    # ── S1–S4 ──
    s1 = rnd(1, 150)
    s2 = rnd(1, 150)
    while s2 == s1 + 56:
        s2 = rnd(1, 150)

    s3 = rnd(1, 64)
    s3_attempts = 0
    while (s3 == s1 + 56 or s3 == s2 + 92) and s3_attempts < 10:
        s3 = rnd(1, 64)
        s3_attempts += 1

    s4 = rnd(1, 32)

    if use_extreme_max:
        s3 = rnd(65, 256)
        s4 = rnd(33, 128)
        s3_attempts = 0
        while (s3 == s1 + 56 or s3 == s2 + 92) and s3_attempts < 10:
            s3 = rnd(65, 256)
            s3_attempts += 1

    # ── Junk Train ──
    min_jc = 4 if version == "1.0" else 3
    max_jc = 128 if use_extreme_max else 15

    jcv = junk_level
    if version == "1.0":
        jcv = max(4, jcv)
    else:
        if jcv > 0:
            variance = rnd(-1, 1)
            jcv = max(1, min(max_jc, jcv + variance))

    if use_extreme_max and junk_level == 0 and version != "1.0":
        jcv = rnd(1, 8)

    jmin_ranges = {"low": (64, 256), "medium": (128, 512), "high": (256, 768)}
    jmax_ranges = {"low": (256, 512), "medium": (512, 1024), "high": (768, 1280)}

    jmin = rnd(*jmin_ranges.get(intensity, (128, 512)))
    jmax = rnd(*jmax_ranges.get(intensity, (512, 1024)))

    min_jmax = jmin + 64
    if jmax < min_jmax:
        jmax = min_jmax + rnd(64, 256)

    if version == "1.0" and jmax <= 81:
        jmax = 82 + rnd(50, 200)

    # ── Router Low-Power Mode ──
    if router_mode:
        s1 = min(s1, 20)
        s2 = min(s2, 20)
        if s2 == s1 + 56:
            s2 = min(s2 + 1, 20)
        jcv = max(min_jc, min(jcv, 2))
        jmin = min(jmin, 40)
        jmax = min(jmax, 128)

    # ── CPS Signature Chain (I1–I5) ──
    has_cps = version != "1.0"
    is_composite = profile in ("tls_to_quic", "quic_burst")
    is_dns = profile == "dns_query"
    mimic_all = inp.get("mimic_all", False)

    i1 = i2 = i3 = i4 = i5 = ""

    if has_cps:
        if is_composite and profile == "tls_to_quic":
            i1 = mk_tls(inp, iv)
            i2 = mk_quic_i(inp, iv)
            i3 = mk_entropy(inp, 2, iv)
            i4 = mk_entropy(inp, 3, iv)
            i5 = mk_entropy(inp, 4, iv)
        elif is_composite and profile == "quic_burst":
            i1 = mk_quic_i(inp, iv)
            i2 = mk_quic_0(inp, iv)
            i3 = mk_http3(inp, iv)
            i4 = mk_entropy(inp, 3, iv)
            i5 = mk_entropy(inp, 4, iv)
        elif is_dns:
            i1 = mk_dns(inp, iv)
            i2 = mk_dns(inp, iv + 1) if mimic_all else mk_entropy(inp, 1, iv)
            i3 = mk_dns(inp, iv + 2) if mimic_all else mk_entropy(inp, 2, iv)
            i4 = mk_dns(inp, iv + 3) if mimic_all else mk_entropy(inp, 3, iv)
            i5 = mk_dns(inp, iv + 4) if mimic_all else mk_entropy(inp, 4, iv)
        else:
            i1 = gen_i1(inp, profile, iv)
            i2 = gen_i1(inp, profile, iv) if mimic_all else mk_entropy(inp, 1, iv)
            i3 = gen_i1(inp, profile, iv) if mimic_all else mk_entropy(inp, 2, iv)
            i4 = gen_i1(inp, profile, iv) if mimic_all else mk_entropy(inp, 3, iv)
            i5 = gen_i1(inp, profile, iv) if mimic_all else mk_entropy(inp, 4, iv)

        if router_mode:
            i2 = i3 = i4 = i5 = ""

    return {
        "version": version,
        "profile": profile,
        # AWG 2.0 range headers
        "H1": h1, "H2": h2, "H3": h3, "H4": h4,
        # AWG 1.x single headers
        "H1s": h1s, "H2s": h2s, "H3s": h3s, "H4s": h4s,
        # Packet size prefixes
        "S1": s1, "S2": s2, "S3": s3, "S4": s4,
        # Junk train
        "Jc": jcv, "Jmin": jmin, "Jmax": jmax,
        # CPS signature chain
        "I1": i1, "I2": i2, "I3": i3, "I4": i4, "I5": i5,
    }


_AWG31_RANGE_FIELDS = (
    # (input key, output conf key)
    ("content_padding_addition", "ContentPaddingAddition"),
    ("rekey_after_time",         "RekeyAfterTime"),
    ("rekey_timeout",            "RekeyTimeout"),
    ("reject_after_time",        "RejectAfterTime"),
    ("keepalive_timeout",        "KeepaliveTimeout"),
    ("max_handshake_attempts",   "MaxHandshakeAttempts"),
)

_RANGE_OR_INT_RE = re.compile(r"^\d+(-\d+)?$")


def gen_awg31_extra(inp: dict) -> dict:
    """
    Generate the optional AmneziaWG 3.1 protocol extras.

    Returns {} if inp["enable_awg31"] is falsy (default — no 3.1 fields are
    written, server stays on plain 2.0-style config).

    Does NOT generate HeaderProtectionKey — that is raw symmetric key
    material and is generated/persisted by app.py (same helper as
    PresharedKey), not by this pure-generator module.

    Numeric fields (ContentPaddingAddition/Rekey*/Keepalive*/MaxHandshake*)
    are amneziawg-tools u16 fields — accept either a single integer "N" or
    a range "min-max" (seconds, except ContentPaddingAddition which is
    bytes). Left out entirely when not provided — the daemon then falls
    back to its own built-in defaults (RekeyAfterTime=120s,
    RekeyTimeout=5s, RejectAfterTime=180s, KeepaliveTimeout=10s,
    MaxHandshakeAttempts=18), which is deliberately the safe default here
    too: we don't invent our own timing values, only pass through what the
    user explicitly set.

    RandomTrailers defaults to False even when enable_awg31=True, because
    of the known unresolved upstream bug (amnezia-vpn/amneziawg-go
    issue #186): RandomTrailers + wide H1-H3 ranges can silently drop a
    fraction of transport packets. The caller (app.py) is expected to
    surface a warning in the UI when the user turns it on.
    """
    if not inp.get("enable_awg31"):
        return {}

    out = {
        "RandomTrailers": bool(inp.get("random_trailers", False)),
        "DisableCookies": bool(inp.get("disable_cookies", False)),
    }
    for in_key, out_key in _AWG31_RANGE_FIELDS:
        val = str(inp.get(in_key, "") or "").strip()
        if not val:
            continue
        if not _RANGE_OR_INT_RE.match(val):
            raise ValueError(f"Invalid {out_key} value: {val!r} (expected \"N\" or \"min-max\")")
        out[out_key] = val
    return out


def default_input() -> dict:
    """Return sensible defaults for generator input."""
    return {
        "version": "2.0",
        "intensity": "medium",
        "profile": "quic_initial",
        "custom_host": "",
        "mimic_all": False,
        # "use_tag_c": False,  # TODO: <c> packet counter — включить когда клиенты AWG добавят поддержку
        "use_tag_t": True,
        "use_tag_r": True,
        "use_tag_rc": True,
        "use_tag_rd": False,
        "use_browser_fp": True,
        "browser_profile": "chrome",
        "mtu": 1280,
        "junk_level": 4,
        "iter_count": 0,
        "router_mode": False,
        "use_extreme_max": False,
        # ── AWG 3.1 extras (all optional, off by default — see gen_awg31_extra()) ──
        "enable_awg31": False,
        "random_trailers": False,   # ⚠ upstream issue #186: packet loss when combined
                                     #   with wide H1-H3 ranges — keep off unless the
                                     #   user explicitly confirms narrow H-ranges.
        "disable_cookies": False,
        "content_padding_addition": "",   # optional "N" or "min-max", bytes
        "rekey_after_time": "",           # optional "N" or "min-max", seconds
        "rekey_timeout": "",
        "reject_after_time": "",
        "keepalive_timeout": "",
        "max_handshake_attempts": "",
    }


if __name__ == "__main__":
    # Quick self-test
    inp = default_input()
    cfg = gen_cfg(inp)
    print("=== AWG Config ===")
    for k, v in cfg.items():
        print(f"  {k}: {v}")
