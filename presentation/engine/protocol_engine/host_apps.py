"""Built-in application catalog keyed on server names (v0.65).

A TLS SNI, QUIC SNI or HTTP Host names the server a client asked for. When that
name falls under a domain operated by one service, the generic carrier verdict
(`ssl`, `quic`, `web-browsing`) is refined to that service. This is the
server-name half of App-ID: the name is a client assertion, never authenticated
identity (domain fronting exists), so the verdict says so and configured
RuleIndex rules and custom signatures always win. With an encrypted
ClientHello the visible SNI is the provider's public front name and is never
mapped (appid.py).

Matching is on DNS label boundaries, longest suffix first: `teams.microsoft.com`
beats `microsoft.com`, and `notyoutube.com` never matches `youtube.com`. Work is
one dictionary probe per label of a name that normalize_hostname already bounded
to 253 bytes. Only domains a single service operates are listed: shared CDNs
and cloud hosting (cloudfront.net, akamaized.net, amazonaws.com, azureedge.net,
...) name no application and are deliberately absent.
"""
from types import MappingProxyType

# (name, category, subcategory, technology, risk, description, characteristics, domains)
_HOST_APPS = (
    # Video, audio and gaming.
    ("youtube", "media", "photo-video", "browser-based", 2, "YouTube video streaming",
     ("excessive-bandwidth", "widely-used", "transfers-files"), ("youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com")),
    ("netflix", "media", "photo-video", "browser-based", 2, "Netflix video streaming",
     ("excessive-bandwidth", "widely-used"), ("netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net")),
    ("twitch", "media", "photo-video", "browser-based", 2, "Twitch live video streaming",
     ("excessive-bandwidth", "widely-used"), ("twitch.tv", "ttvnw.net", "jtvnw.net")),
    ("disney-plus", "media", "photo-video", "browser-based", 2, "Disney+ video streaming",
     ("excessive-bandwidth",), ("disneyplus.com", "dssott.com", "bamgrid.com")),
    ("hulu", "media", "photo-video", "browser-based", 2, "Hulu video streaming", ("excessive-bandwidth",), ("hulu.com", "hulustream.com")),
    ("amazon-prime-video", "media", "photo-video", "browser-based", 2, "Amazon Prime Video streaming",
     ("excessive-bandwidth",), ("primevideo.com", "aiv-cdn.net", "aiv-delivery.net")),
    ("vimeo", "media", "photo-video", "browser-based", 2, "Vimeo video hosting", ("excessive-bandwidth", "transfers-files"), ("vimeo.com", "vimeocdn.com")),
    ("tiktok", "media", "photo-video", "browser-based", 3, "TikTok short-video platform",
     ("excessive-bandwidth", "widely-used", "transfers-files"), ("tiktok.com", "tiktokcdn.com", "tiktokv.com", "tiktokcdn-us.com")),
    ("spotify", "media", "audio-streaming", "client-server", 2, "Spotify music and podcast streaming",
     ("excessive-bandwidth", "widely-used"), ("spotify.com", "scdn.co", "spotifycdn.com", "spotify.design")),
    ("steam", "media", "gaming", "client-server", 3, "Valve Steam store, community and downloads",
     ("excessive-bandwidth", "transfers-files"), ("steampowered.com", "steamcommunity.com", "steamcontent.com", "steamstatic.com")),
    # Social networking.
    ("facebook", "collaboration", "social-networking", "browser-based", 3, "Facebook social network",
     ("widely-used", "transfers-files", "prone-to-misuse"), ("facebook.com", "fbcdn.net", "fb.com", "facebook.net", "fbsbx.com")),
    ("instagram", "collaboration", "social-networking", "browser-based", 3, "Instagram photo and video sharing",
     ("widely-used", "transfers-files"), ("instagram.com", "cdninstagram.com")),
    ("twitter", "collaboration", "social-networking", "browser-based", 3, "X (Twitter) social network",
     ("widely-used", "transfers-files"), ("twitter.com", "x.com", "twimg.com", "t.co")),
    ("linkedin", "collaboration", "social-networking", "browser-based", 2, "LinkedIn professional network",
     ("widely-used",), ("linkedin.com", "licdn.com")),
    ("reddit", "collaboration", "social-networking", "browser-based", 3, "Reddit forums",
     ("widely-used", "transfers-files"), ("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com")),
    ("pinterest", "collaboration", "social-networking", "browser-based", 2, "Pinterest image sharing", ("transfers-files",), ("pinterest.com", "pinimg.com")),
    ("snapchat", "collaboration", "social-networking", "client-server", 3, "Snapchat messaging and stories",
     ("transfers-files",), ("snapchat.com", "sc-cdn.net", "snap-dev.net")),
    # Messaging and meetings.
    ("whatsapp", "collaboration", "instant-messaging", "client-server", 3, "WhatsApp messaging and calls",
     ("widely-used", "transfers-files", "evasive"), ("whatsapp.com", "whatsapp.net")),
    ("telegram", "collaboration", "instant-messaging", "client-server", 4, "Telegram messaging",
     ("transfers-files", "evasive", "prone-to-misuse"), ("telegram.org", "t.me", "telegram.me", "telesco.pe")),
    ("signal", "collaboration", "instant-messaging", "client-server", 3, "Signal end-to-end encrypted messaging",
     ("transfers-files", "evasive"), ("signal.org", "signal.art", "whispersystems.org")),
    ("discord", "collaboration", "instant-messaging", "client-server", 3, "Discord chat, voice and communities",
     ("widely-used", "transfers-files", "prone-to-misuse"), ("discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media")),
    ("slack", "collaboration", "instant-messaging", "browser-based", 2, "Slack team messaging",
     ("widely-used", "transfers-files"), ("slack.com", "slack-edge.com", "slack-msgs.com", "slack-files.com")),
    ("zoom", "collaboration", "voip-video", "client-server", 2, "Zoom meetings",
     ("widely-used", "excessive-bandwidth"), ("zoom.us", "zoom.com", "zoomgov.com")),
    ("ms-teams", "collaboration", "voip-video", "client-server", 2, "Microsoft Teams chat and meetings",
     ("widely-used", "transfers-files"), ("teams.microsoft.com", "teams.live.com", "teams.cdn.office.net")),
    ("skype", "collaboration", "voip-video", "client-server", 3, "Skype calls and messaging", ("transfers-files", "evasive"), ("skype.com", "skypeassets.com")),
    ("webex", "collaboration", "voip-video", "client-server", 2, "Cisco Webex meetings", ("widely-used",), ("webex.com", "wbx2.com")),
    ("google-meet", "collaboration", "voip-video", "browser-based", 2, "Google Meet video meetings", ("widely-used",), ("meet.google.com",)),
    # Email.
    ("gmail", "collaboration", "email", "browser-based", 2, "Gmail web mail", ("widely-used", "transfers-files"), ("mail.google.com", "gmail.com")),
    ("outlook-web", "collaboration", "email", "browser-based", 2, "Outlook web mail (Microsoft 365 and Outlook.com)",
     ("widely-used", "transfers-files"), ("outlook.office365.com", "outlook.office.com", "outlook.live.com", "outlook.com")),
    # Office, storage and business services.
    ("ms-office365", "business-systems", "office-programs", "browser-based", 2, "Microsoft 365 web applications",
     ("widely-used", "transfers-files"), ("office.com", "office365.com", "office.net", "officeapps.live.com")),
    ("sharepoint-online", "business-systems", "office-programs", "browser-based", 2, "SharePoint Online sites and files",
     ("widely-used", "transfers-files"), ("sharepoint.com",)),
    ("ms-onedrive", "general-internet", "file-sharing", "browser-based", 3, "Microsoft OneDrive file storage",
     ("widely-used", "transfers-files"), ("onedrive.live.com", "onedrive.com", "1drv.com", "1drv.ms")),
    ("azure-ad", "business-systems", "auth-service", "browser-based", 1, "Microsoft Entra ID (Azure AD) sign-in",
     ("widely-used",), ("login.microsoftonline.com", "microsoftonline.com", "login.live.com")),
    ("ms-update", "business-systems", "software-development", "client-server", 1, "Windows Update and Microsoft software delivery",
     ("widely-used", "transfers-files", "excessive-bandwidth"), ("windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com")),
    ("google-drive", "general-internet", "file-sharing", "browser-based", 3, "Google Drive and Docs",
     ("widely-used", "transfers-files"), ("drive.google.com", "docs.google.com", "drive.usercontent.google.com")),
    ("google-base", "general-internet", "internet-utility", "browser-based", 2, "Google services not mapped to a more specific application",
     ("widely-used", "pervasive"), ("google.com", "gstatic.com", "googleapis.com", "googleusercontent.com", "gvt1.com", "gvt2.com")),
    ("dropbox", "general-internet", "file-sharing", "client-server", 3, "Dropbox file sync and sharing",
     ("widely-used", "transfers-files"), ("dropbox.com", "dropboxapi.com", "dropboxusercontent.com", "dropboxstatic.com")),
    ("box", "general-internet", "file-sharing", "browser-based", 2, "Box content management", ("transfers-files",), ("box.com", "boxcloud.com", "box.net")),
    ("icloud", "general-internet", "file-sharing", "client-server", 2, "Apple iCloud services", ("widely-used", "transfers-files"), ("icloud.com", "icloud-content.com")),
    ("github", "business-systems", "software-development", "browser-based", 2, "GitHub code hosting",
     ("widely-used", "transfers-files"), ("github.com", "githubusercontent.com", "githubassets.com", "github.io")),
    ("gitlab", "business-systems", "software-development", "browser-based", 2, "GitLab code hosting", ("transfers-files",), ("gitlab.com",)),
    ("atlassian", "business-systems", "software-development", "browser-based", 2, "Atlassian cloud (Jira, Confluence, Bitbucket)",
     ("widely-used", "transfers-files"), ("atlassian.net", "atlassian.com", "bitbucket.org")),
    ("salesforce", "business-systems", "general-business", "browser-based", 2, "Salesforce CRM", ("widely-used", "transfers-files"), ("salesforce.com", "force.com")),
    ("notion", "business-systems", "office-programs", "browser-based", 2, "Notion workspace", ("transfers-files",), ("notion.so", "notion.site")),
    # Generative AI.
    ("openai-chatgpt", "business-systems", "generative-ai", "browser-based", 3, "OpenAI ChatGPT and API",
     ("transfers-files", "widely-used"), ("openai.com", "chatgpt.com", "oaiusercontent.com", "oaistatic.com")),
    ("anthropic-claude", "business-systems", "generative-ai", "browser-based", 3, "Anthropic Claude",
     ("transfers-files",), ("claude.ai", "anthropic.com", "claude.com")),
    ("google-gemini", "business-systems", "generative-ai", "browser-based", 3, "Google Gemini", ("transfers-files",), ("gemini.google.com",)),
    # Remote access.
    ("teamviewer", "networking", "remote-access", "client-server", 4, "TeamViewer remote control",
     ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("teamviewer.com",)),
    ("anydesk", "networking", "remote-access", "client-server", 4, "AnyDesk remote control",
     ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("anydesk.com", "net.anydesk.com")),
    # Commerce and reference.
    ("amazon", "general-internet", "internet-utility", "browser-based", 2, "Amazon retail site", ("widely-used",), ("amazon.com", "media-amazon.com", "ssl-images-amazon.com")),
    ("ebay", "general-internet", "internet-utility", "browser-based", 2, "eBay marketplace", (), ("ebay.com", "ebayimg.com", "ebaystatic.com")),
    ("paypal", "business-systems", "general-business", "browser-based", 2, "PayPal payments", ("widely-used",), ("paypal.com", "paypalobjects.com")),
    ("wikipedia", "general-internet", "internet-utility", "browser-based", 1, "Wikipedia and Wikimedia projects", ("widely-used",), ("wikipedia.org", "wikimedia.org")),
)

APP_DOMAINS = MappingProxyType({name: domains for name, *_, domains in _HOST_APPS})
_SUFFIXES = {}
for _name, *_rest, _domains in _HOST_APPS:
    for _domain in _domains:
        if _domain in _SUFFIXES:
            raise ValueError("Duplicate host-catalog domain " + _domain)
        _SUFFIXES[_domain] = _name
HOST_SUFFIXES = MappingProxyType(_SUFFIXES)
del _name, _rest, _domains, _domain, _SUFFIXES


def catalog_entries(make):
    """Application entries for applications.py, built with its `_app` constructor."""
    return tuple(make(name, category, subcategory, technology, risk, description, characteristics,
                      implicitly_uses=("ssl", "web-browsing"))
                 for name, category, subcategory, technology, risk, description, characteristics, _ in _HOST_APPS)


def application_for_host(hostname):
    """Catalog application for a normalized server name (longest label-boundary suffix), or None."""
    position = 0
    while True:
        name = HOST_SUFFIXES.get(hostname[position:])
        if name is not None:
            return name
        dot = hostname.find(".", position)
        if dot < 0:
            return None
        position = dot + 1
