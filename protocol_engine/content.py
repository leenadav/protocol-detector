"""D08: detection content versioning, provenance, review dates and rollback.

"Content" is the administrative data a verdict is looked up in once a structural
identification exists: the built-in server-name catalog (host_apps.py), the
application catalog (applications.py), the family inventory (catalog.py) and the
flow-risk table (risks.py). Parsers are engine code and follow the package
version; content has its own release history so that a session record can say
which catalog classified it, a reviewer can see when each entry was last looked
at, and an operator can run an earlier catalog (`select(version)`) without
changing the engine.

Releases are `YYYY.MM.N`. `content_lock.json` next to this module records the
digest of the current content; `tools/check_content.py` fails when the content
changed without a new release entry, so every catalog edit is dated and named.
Rollback covers the server-name catalog, whose earlier states are kept here as
the differences from the current entries; the application catalog and the family
inventory change only with engine releases and roll back with the package.
"""
import hashlib
import json
from collections import namedtuple
from pathlib import Path
from types import MappingProxyType

Release = namedtuple("Release", "version released reviewed review note")

HISTORY = (
    Release("2025.10.0", "2025-10-24", "2025-10-24",
            "engine-lane self-review; independent Codex rounds on v0.65 (issue #2)",
            "v0.65 built-in server-name catalog: 51 services on operator-owned domains"),
    Release("2026.11.0", "2026-11-07", "2026-11-07",
            "engine-lane self-review (D03); independent review pending on PR #18",
            "provider web fronts separated from service domains; OpenAI split into ChatGPT, platform and web front; "
            "github.io (tenant hosting) removed; TeamViewer/AnyDesk apex and www names are web fronts"),
    Release("2026.11.1", "2026-11-15", "2026-11-15",
            "engine-lane self-review against the operator-owned-domain rule; independent review pending",
            "115 more services on operator-owned domains (streaming, gaming, social, messaging, storage, business, "
            "developer, identity, generative AI, remote access, VPN, encrypted-DNS resolvers, platform bases, search, "
            "commerce); remote-access and VPN apex/www names are web fronts"),
    Release("2026.11.2", "2026-11-15", "2026-11-15",
            "engine-lane self-review against the operator-owned-domain rule; independent review pending",
            "262 more services on operator-owned domains (media, social, messaging, mail, storage and backup, business, "
            "management and endpoint security, developer, identity, generative AI, remote access and RMM, VPN and "
            "circumvention, cloud proxies, resolvers, commerce, news, education, advertising and measurement); "
            "remote-access, RMM and VPN apex/www names are web fronts"),
    Release("2026.11.3", "2026-11-18", "2026-11-18",
            "application-research lane proposal with primary sources (research/apps on claude/app-research 9c040b2); "
            "engine-lane review of each spec against its sources; independent review pending",
            "Microsoft 365 cloud.microsoft names and Exchange Online Protection separated from web mail; Copilot "
            "app host; GitHub Copilot service hosts; Anthropic API split from the apps; Dropbox verified domains, "
            "web fronts and DocSend"),
    Release("2026.11.4", "2026-11-18", "2026-11-18",
            "application-research lane proposal with primary sources (research/apps on claude/app-research bb931b9); "
            "engine-lane review of each spec against its sources; independent review pending",
            "Google Drive and Docs editor hosts; OneDrive consumer hosts; Webex service domains; OpenAI help and "
            "developer documentation as web fronts"),
    Release("2026.11.5", "2026-11-18", "2026-11-18",
            "application-research lane proposal with primary sources (research/apps on claude/app-research bb931b9); "
            "API split for these vendors decided by Hermes; engine-lane review of each spec; independent review pending",
            "DeepSeek, Perplexity, Mistral AI and xAI API hosts named apart from their chat applications"),
    Release("2026.11.6", "2026-11-18", "2026-11-18",
            "application-research lane proposal with primary sources (research/apps on claude/app-research dc75176); "
            "engine-lane review of each spec against its sources; independent review pending",
            "notebook.google.com; Dropbox www web fronts; ngrok agent hosts; Cloudflare One Client API hosts; "
            "Atlassian first-party domains; WeTransfer short links and named storage hosts"),
    Release("2026.11.7", "2026-11-19", "2026-11-19",
            "application-research lane proposal with primary sources (research/apps on claude/app-research 7a8d4d7); "
            "engine-lane review of each spec against its sources; independent review pending",
            "Defender for Endpoint and Intune; iCloud Private Relay apart from iCloud; Cursor, 1Password, GitLab, Docker, "
            "Okta, Notion, GoTo Meeting, Zscaler, Figma for Government and Netskope hosts from vendor documentation"),
)
CURRENT = HISTORY[-1].version
LOCK_PATH = Path(__file__).with_name("content_lock.json")

# Server-name catalog entries as they were at an earlier release, where they differ from the current
# tables: None means the entry did not exist yet; a dict names the fields that were different.
# Entry layout (host_apps._HOST_APPS): name, category, subcategory, technology, risk, description,
# characteristics, domains, web_fronts (optional).
# Entries first released in 2026.11.1 (absent from every earlier release).
_ADDED_2026_11_1 = (
    "hbo-max", "paramount-plus", "peacock", "dailymotion", "apple-tv", "apple-music", "soundcloud", "deezer",
    "pandora", "epic-games", "roblox", "xbox-live", "playstation-network", "nintendo", "ea-games", "battle-net",
    "riot-games", "threads", "tumblr", "quora", "vk", "bluesky", "weibo", "facebook-messenger", "line", "wechat",
    "viber", "threema", "matrix-element", "goto-meeting", "ringcentral", "yahoo-mail", "proton-mail", "zoho",
    "mega", "wetransfer", "mediafire", "pcloud", "pastebin", "servicenow", "workday", "hubspot", "zendesk",
    "docusign", "stripe", "coinbase", "binance", "adobe-cloud", "canva", "figma", "miro", "trello", "asana",
    "monday", "airtable", "evernote", "grammarly", "docker-hub", "npm", "pypi", "stack-overflow", "jetbrains",
    "apple-app-store", "google-play", "okta", "duo-security", "auth0", "google-accounts", "1password", "lastpass",
    "bitwarden", "ms-copilot", "github-copilot", "perplexity", "mistral-ai", "deepseek", "xai-grok", "hugging-face",
    "midjourney", "character-ai", "poe", "logmein", "splashtop", "rustdesk", "chrome-remote-desktop", "nordvpn",
    "expressvpn", "proton-vpn", "surfshark", "mullvad", "tailscale", "zerotier", "cloudflare-dns",
    "google-public-dns", "quad9-dns", "nextdns", "adguard-dns", "apple-base", "apple-push", "ms-base", "yahoo",
    "bing", "duckduckgo", "baidu", "yandex", "google-ads", "google-analytics", "speedtest", "aliexpress", "walmart",
    "etsy", "shopify", "booking", "airbnb", "uber",
)
# Entries first released in 2026.11.2.
_ADDED_2026_11_2 = (
    "crunchyroll", "plex", "kick", "rumble", "bilibili", "espn", "dazn", "discovery-plus", "tidal", "audible",
    "bandcamp", "iheartradio", "tunein", "gog", "ubisoft-connect", "minecraft", "unity", "nextdoor", "flickr",
    "imgur", "9gag", "medium", "substack", "wordpress-com", "goodreads", "strava", "tinder", "bumble", "kakaotalk",
    "zalo", "groupme", "google-chat", "intercom", "google-voice", "whereby", "jitsi-meet", "8x8", "dialpad",
    "twilio", "vonage", "mailchimp", "sendgrid", "fastmail", "tuta-mail", "yandex-mail", "gmx-mail", "aol",
    "google-photos", "gofile", "file-io", "transfer-sh", "catbox", "4shared", "sendspace", "sync-com", "egnyte",
    "backblaze", "idrive", "sap", "oracle-cloud", "netsuite", "intuit", "xero", "freshworks", "gusto", "adp",
    "bamboohr", "sap-concur", "expensify", "revolut", "wise", "venmo", "cash-app", "robinhood", "kraken",
    "metamask", "wix", "squarespace", "godaddy", "namecheap", "tableau", "power-bi", "smartsheet", "clickup",
    "basecamp", "calendly", "typeform", "surveymonkey", "lucid", "dropbox-sign", "pandadoc", "snowflake",
    "databricks", "splunk-cloud", "datadog", "new-relic", "sentry", "pagerduty", "crowdstrike", "sentinelone",
    "virustotal", "malwarebytes", "kaspersky", "norton", "mcafee", "avast", "bitdefender", "eset", "sophos",
    "ms-telemetry", "apple-software-update", "mozilla", "android-services", "samsung", "xiaomi", "huawei",
    "sourceforge", "circleci", "vercel", "netlify", "heroku", "digitalocean", "linode", "maven-central", "rubygems",
    "crates-io", "go-modules", "nuget", "packagist", "gradle", "visual-studio", "postman", "sonarcloud", "snyk",
    "codepen", "replit", "kaggle", "google-colab", "ubuntu", "debian", "fedora", "homebrew", "onelogin",
    "ping-identity", "jumpcloud", "dashlane", "keeper", "authy", "lets-encrypt", "digicert", "cohere", "replicate",
    "stability-ai", "elevenlabs", "runway", "jasper-ai", "copy-ai", "writesonic", "cursor", "windsurf", "tabnine",
    "together-ai", "groq", "openrouter", "meta-ai", "suno", "phind", "you-com", "doubao", "baidu-ernie",
    "alibaba-tongyi", "zhipu-ai", "google-ai-studio", "google-notebooklm", "beyondtrust", "connectwise-control",
    "parsec", "nomachine", "remotepc", "gotomypc", "ammyy-admin", "supremo", "atera", "ninjaone", "kaseya",
    "dwservice", "getscreen", "ngrok", "zoho-assist", "cyberghost", "private-internet-access", "ipvanish",
    "windscribe", "tunnelbear", "hotspot-shield", "hide-me", "psiphon", "ultrasurf", "lantern", "tor-project",
    "cloudflare-warp", "zscaler", "netskope", "opendns", "cleanbrowsing-dns", "controld-dns", "dns-sb",
    "google-maps", "waze", "openstreetmap", "target", "best-buy", "costco", "ikea", "temu", "shein", "mercadolibre",
    "rakuten", "flipkart", "taobao", "jd-com", "alibaba", "craigslist", "doordash", "instacart", "expedia",
    "tripadvisor", "nytimes", "bbc", "cnn", "reuters", "the-guardian", "imdb", "weather-com", "internet-archive",
    "coursera", "udemy", "khan-academy", "duolingo", "canvas-lms", "blackboard", "quizlet", "amazon-ads", "criteo",
    "taboola", "outbrain", "appsflyer", "adjust", "mixpanel", "segment", "hotjar", "amplitude", "branch-io",
    "onesignal", "braze", "scorecard-research", "quantcast", "the-trade-desk", "pubmatic", "magnite", "openx",
    "xandr",
)
_PRIOR_HOST_STATE = MappingProxyType({
    "2026.11.6": MappingProxyType({
        "icloud": {"domains": ("icloud.com", "icloud-content.com")},
        "icloud-private-relay": None,
        "cursor": {"domains": ("cursor.com", "cursor.sh")},
        "1password": {"domains": ("1password.com", "1password.eu")},
        "gitlab": {"domains": ("gitlab.com",)},
        "docker-hub": {"domains": ("docker.com", "docker.io")},
        "okta": {"domains": ("okta.com", "oktacdn.com", "oktapreview.com")},
        "notion": {"domains": ("notion.so", "notion.site")},
        "goto-meeting": {"domains": ("gotomeeting.com", "goto.com")},
        "zscaler": {"domains": ("zscaler.com", "zscaler.net", "zscloud.net")},
        "figma": {"domains": ("figma.com",)},
        "netskope": {"domains": ("netskope.com", "goskope.com")},
        "ms-defender-endpoint": None,
        "ms-intune": None,
    }),
    "2026.11.5": MappingProxyType({
        "google-notebooklm": {"domains": ("notebooklm.google.com",)},
        "dropbox": {"web_fronts": ("dropboxforum.com", "dropboxforums.com", "dropboxlegal.com", "dropboxinsiders.com",
                                   "dropbox.tech", "learn.dropbox.com")},
        "ngrok": {"domains": ("ngrok.com",)},
        "cloudflare-warp": {"domains": ("cloudflareclient.com",)},
        "atlassian": {"domains": ("atlassian.net", "atlassian.com", "bitbucket.org")},
        "wetransfer": {"domains": ("wetransfer.com", "wetransfer.net")},
    }),
    "2026.11.4": MappingProxyType({"deepseek-api": None, "perplexity-api": None, "mistral-api": None, "xai-api": None}),
    "2026.11.3": MappingProxyType({
        "google-drive": {"domains": ("drive.google.com", "docs.google.com", "drive.usercontent.google.com")},
        "ms-onedrive": {"description": "Microsoft OneDrive file storage",
                        "domains": ("onedrive.live.com", "onedrive.com", "1drv.com", "1drv.ms")},
        "webex": {"domains": ("webex.com", "wbx2.com")},
        "openai-chatgpt": {"web_fronts": ("openai.com", "www.openai.com")},
        "openai-platform": {"web_fronts": ()},
    }),
    "2026.11.2": MappingProxyType({
        "ms-teams": {"domains": ("teams.microsoft.com", "teams.live.com", "teams.cdn.office.net")},
        "outlook-web": {"domains": ("outlook.office365.com", "outlook.office.com", "outlook.live.com", "outlook.com")},
        "ms-exchange-online-protection": None,
        "ms-office365": {"domains": ("office.com", "office365.com", "office.net", "officeapps.live.com")},
        "sharepoint-online": {"domains": ("sharepoint.com",)},
        "ms-copilot": {"domains": ("copilot.microsoft.com",)},
        "github-copilot": {"domains": ("githubcopilot.com",)},
        "anthropic-claude": {"domains": ("claude.ai", "anthropic.com", "claude.com"), "web_fronts": ()},
        "anthropic-api": None,
        "dropbox": {"domains": ("dropbox.com", "dropboxapi.com", "dropboxusercontent.com", "dropboxstatic.com"),
                    "web_fronts": ()},
        "docsend": None,
        "dropbox-sign": {"domains": ("hellosign.com",)},
    }),
    "2026.11.1": MappingProxyType({name: None for name in _ADDED_2026_11_2}),
    "2026.11.0": MappingProxyType({name: None for name in _ADDED_2026_11_1}),
    "2025.10.0": MappingProxyType({
        "github": {"domains": ("github.com", "githubusercontent.com", "githubassets.com", "github.io"), "web_fronts": ()},
        "openai-chatgpt": {"description": "OpenAI ChatGPT and API",
                           "domains": ("openai.com", "chatgpt.com", "oaiusercontent.com", "oaistatic.com"), "web_fronts": ()},
        "openai-platform": None,
        "teamviewer": {"web_fronts": ()},
        "anydesk": {"web_fronts": ()},
    }),
})
_FIELDS = ("name", "category", "subcategory", "technology", "risk", "description", "characteristics", "domains", "web_fronts")
# Provenance of server-name entries: how a domain earns its place and how it is checked.
HOST_BASIS = "operator-owned-domain"
HOST_SOURCE = "public domain ownership and the service's own documentation; shared CDNs, cloud hosting and tenant domains excluded"


class ContentError(ValueError):
    pass


def releases():
    return HISTORY


def release(version):
    for item in HISTORY:
        if item.version == version:
            return item
    raise ContentError("Unknown content version " + repr(version))


def _entry_dict(entry):
    values = dict(zip(_FIELDS, entry))
    values.setdefault("web_fronts", ())
    return values


def host_entries(version=None):
    """Server-name catalog entries (dicts) as of `version` (default: current)."""
    from .host_apps import _HOST_APPS
    version = CURRENT if version is None else version
    release(version)
    entries = [_entry_dict(entry) for entry in _HOST_APPS]
    for item in reversed(HISTORY):
        if item.version < version:
            break
        prior = _PRIOR_HOST_STATE.get(item.version)
        if not prior:
            continue
        rebuilt = []
        for entry in entries:
            change = prior.get(entry["name"], {})
            if change is None:
                continue
            rebuilt.append(dict(entry, **change))
        entries = rebuilt
    return tuple(entries)


def host_provenance(version=None):
    """Per-entry provenance: first release carrying the entry, last review date, basis and source."""
    version = CURRENT if version is None else version
    current = {entry["name"] for entry in host_entries(version)}
    first = {}
    for item in HISTORY:
        if item.version > version:
            break
        for entry in host_entries(item.version):
            first.setdefault(entry["name"], item.version)
    reviewed = release(version).reviewed
    return MappingProxyType({name: MappingProxyType({"since": first[name], "reviewed": reviewed, "basis": HOST_BASIS, "source": HOST_SOURCE})
                             for name in sorted(current)})


def _hash(parts):
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(json.dumps(part, sort_keys=True, default=str).encode("utf-8"))
        hasher.update(b"\0")
    return hasher.hexdigest()


# C11 (2026-11-18): the components each earlier release was published with, so that its digest, which records
# pinned to it carry, is reproduced exactly by a rollback. They are the release's content_lock.json while it was
# current; 2025.10.0, released before the lock existed, as first recorded (799d358). A rollback rebuilds the host
# catalog, which must equal the recorded host component (check() and component_digests refuse otherwise); the
# application catalog, families and risks are engine metadata that follow the package (docs/CONTENT-GOVERNANCE.md,
# "Rollback") and are stated as released. Adding a release moves the previous one here, from its lock.
_RELEASED_COMPONENTS = MappingProxyType({
    "2025.10.0": MappingProxyType({
        "application_catalog": "4e37559adfe72232473e05c2cf77ecc979ae3426b4a6cd5494ec3f17f4517195",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "66f39d536827348c9cd1d3928f36d33b2ef8f1952e15e0dd262ca0c4c8938e5f",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.0": MappingProxyType({
        "application_catalog": "4e37559adfe72232473e05c2cf77ecc979ae3426b4a6cd5494ec3f17f4517195",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "928b856e40db5873d64db50ba81dfac5e07e44eb3c5c86b8009340f5eca1f17c",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.1": MappingProxyType({
        "application_catalog": "2b61c2aaf2e51fff1ccdaf479673082e6b300cd2649cf960c1f139295bd63b90",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "d90de751d3e9f4ac4602deca7637f3e2164fc6ed7ccd8cb292a99ccd54fa43fe",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.2": MappingProxyType({
        "application_catalog": "f5205651ca01a87a4004caeed18b0b6be38cfd627a565b0d4a007fa209935eb7",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "82e1abd27dad3f3ee04cb80939a9ab81f099631f06e23d94fb75e6071afd1c7d",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.3": MappingProxyType({
        "application_catalog": "f82444035f260b95537ed83be8d7e80998c79727272a161b1d529839f797118b",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "184c9d5d0812aa155855d75a8b6c0bb2d0f174292868fdbe1ac611f10f4776fb",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.4": MappingProxyType({
        "application_catalog": "5223dae2810e6760888e005a40ef308721c58d38d35d697603c08d1b919da441",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "5ef1561c0cafa644c3fd445e67b32a8c5916e7fbf1a41819e6eaac582d67ec12",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.5": MappingProxyType({
        "application_catalog": "f96fe05e0855fbec4c13a767f62384f409474c8f19e1e4d202202c1e2e936b41",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "9525e84c0367c0fa43376c6b16358172581f3a4367e17d2e350ea4f35eea35d0",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
    "2026.11.6": MappingProxyType({
        "application_catalog": "f96fe05e0855fbec4c13a767f62384f409474c8f19e1e4d202202c1e2e936b41",
        "families": "3d0a1c192ef2b70e2a1a4cb920ad282f450e38b4fec61a172f0d4474417f1649",
        "host_catalog": "f463fce893f7a9d4cd37da585971f6068dd7c112a26975ffba886560b7e5232b",
        "risks": "59352a1c2a2366f804bf6f3427d255d36c0e668c5b3d579c3b3d29db23cf0c85"}),
})


def _host_component(version):
    return _hash([entry for entry in host_entries(version)])


def component_digests(version=None):
    """Digest per content component. The current release's are computed from the tables; an earlier release's
    are the ones it was published with (C11), after its rebuilt host catalog is checked against them."""
    version = CURRENT if version is None else version
    if version != CURRENT:
        release(version)
        recorded = _RELEASED_COMPONENTS.get(version)
        if recorded is None:
            raise ContentError("content release {} has no recorded components".format(version))
        if _host_component(version) != recorded["host_catalog"]:
            raise ContentError("content release {} no longer reproduces its host catalog".format(version))
        return MappingProxyType(dict(recorded))
    from .applications import APPLICATIONS
    from .catalog import supported_protocols
    from .risks import RISKS
    return MappingProxyType({
        "host_catalog": _host_component(version),
        "application_catalog": _hash([(name, list(app.__dict__.values())) for name, app in sorted(APPLICATIONS.items())]),
        "families": _hash([(item.family, list(item.transports), item.scope, item.profile, item.requires_hint) for item in supported_protocols()]),
        "risks": _hash([(name, list(RISKS[name])) for name in sorted(RISKS)]),
    })


_DIGESTS = {}


def digest(version=None):
    """Content digest for a release; cached per process (the tables of a release never change at run time)."""
    version = CURRENT if version is None else version
    cached = _DIGESTS.get(version)
    if cached is None:
        components = component_digests(version)
        cached = _DIGESTS[version] = _hash([components[name] for name in sorted(components)])[:16]
    return cached


def description(version=None):
    """The content release with its digests, for `protodetect content` and the lock file."""
    version = CURRENT if version is None else version
    item = release(version)
    return {"version": item.version, "released": item.released, "reviewed": item.reviewed, "review": item.review,
            "note": item.note, "digest": digest(version), "components": dict(component_digests(version)),
            "host_entries": len(host_entries(version))}


# -- process-wide selection (rollback) --

_SELECTED = [CURRENT]


def select(version):
    """Run the server-name catalog as of `version` in this process; returns the pin for records."""
    from . import host_apps
    release(version)
    host_apps.rebuild(host_entries(version))
    _SELECTED[0] = version
    return pinned()


def selected():
    return _SELECTED[0]


def pinned():
    """What a session record pins: the content version in force and its digest."""
    return {"version": _SELECTED[0], "digest": digest(_SELECTED[0])}


# -- lock file --

def read_lock(path=LOCK_PATH):
    with open(path, "rb") as handle:
        return json.loads(handle.read().decode("utf-8"))


def write_lock(path=LOCK_PATH):
    data = description()
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def check(path=LOCK_PATH):
    """Problems between the content tables, the release history and the lock file (empty when consistent)."""
    problems = []
    versions = [item.version for item in HISTORY]
    if versions != sorted(versions) or len(set(versions)) != len(versions):
        problems.append("content releases are not strictly increasing")
    for item in HISTORY:
        for field in ("released", "reviewed"):
            value = getattr(item, field)
            if len(value) != 10 or value[4] != "-" or value[7] != "-" or not (value[:4] + value[5:7] + value[8:]).isdigit():
                problems.append("release {} has a malformed {} date".format(item.version, field))
    for version in _PRIOR_HOST_STATE:
        if version not in versions:
            problems.append("prior host state for unknown release " + version)
    names = {entry["name"] for entry in host_entries()}
    for version, prior in _PRIOR_HOST_STATE.items():
        for name, change in prior.items():
            if name not in names:
                problems.append("prior state of {} names an unknown entry {}".format(version, name))
            elif change is not None and not set(change) <= set(_FIELDS):
                problems.append("prior state of {} changes unknown fields of {}".format(version, name))
    for item in HISTORY:
        try:
            from .host_apps import build_tables
            build_tables(host_entries(item.version))
        except (ValueError, ContentError) as error:
            problems.append("catalog at {} does not build: {}".format(item.version, error))
    for item in HISTORY[:-1]:
        recorded = _RELEASED_COMPONENTS.get(item.version)
        if recorded is None:
            problems.append("release {} has no recorded components (move its lock into _RELEASED_COMPONENTS)".format(item.version))
        elif _host_component(item.version) != recorded["host_catalog"]:
            problems.append("release {} no longer reproduces its recorded host catalog".format(item.version))
    for version in _RELEASED_COMPONENTS:
        if version not in versions[:-1]:
            problems.append("recorded components for {}, which is not an earlier release".format(version))
    try:
        lock = read_lock(path)
    except (OSError, ValueError):
        problems.append("content lock missing or unreadable: run tools/check_content.py --update after adding a release")
        return problems
    current = description()
    if lock.get("version") != current["version"]:
        problems.append("content lock names {} but the current release is {}".format(lock.get("version"), current["version"]))
    if lock.get("digest") != current["digest"]:
        changed = sorted(name for name, value in current["components"].items() if lock.get("components", {}).get(name) != value)
        problems.append("content changed ({}) without a new release entry: add a Release to protocol_engine/content.py HISTORY, "
                        "then run tools/check_content.py --update".format(", ".join(changed) or "digest"))
    elif lock.get("components") != current["components"] or lock.get("host_entries") != current["host_entries"]:
        # The aggregate agrees but the lock's own metadata does not: a hand-edited or stale lock file.
        problems.append("content lock metadata is inconsistent with the tables (per-component digests or host_entries differ while "
                        "the aggregate digest matches): regenerate it with tools/check_content.py --update")
    return problems
