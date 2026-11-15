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
    # github.io is tenant hosting (user and project pages): an arbitrary tenant is not GitHub and gets no mapping (D03).
    ("github", "business-systems", "software-development", "browser-based", 2, "GitHub code hosting",
     ("widely-used", "transfers-files"), ("github.com", "githubusercontent.com", "githubassets.com")),
    ("gitlab", "business-systems", "software-development", "browser-based", 2, "GitLab code hosting", ("transfers-files",), ("gitlab.com",)),
    ("atlassian", "business-systems", "software-development", "browser-based", 2, "Atlassian cloud (Jira, Confluence, Bitbucket)",
     ("widely-used", "transfers-files"), ("atlassian.net", "atlassian.com", "bitbucket.org")),
    ("salesforce", "business-systems", "general-business", "browser-based", 2, "Salesforce CRM", ("widely-used", "transfers-files"), ("salesforce.com", "force.com")),
    ("notion", "business-systems", "office-programs", "browser-based", 2, "Notion workspace", ("transfers-files",), ("notion.so", "notion.site")),
    # Generative AI.
    # D03: ChatGPT (the assistant), the developer platform/API and the provider's web presence are three things.
    ("openai-chatgpt", "business-systems", "generative-ai", "browser-based", 3, "OpenAI ChatGPT",
     ("transfers-files", "widely-used"), ("chatgpt.com", "chat.openai.com", "oaiusercontent.com", "oaistatic.com"), ("openai.com", "www.openai.com")),
    ("openai-platform", "business-systems", "generative-ai", "client-server", 3, "OpenAI developer platform and API",
     ("transfers-files",), ("api.openai.com", "platform.openai.com")),
    ("anthropic-claude", "business-systems", "generative-ai", "browser-based", 3, "Anthropic Claude",
     ("transfers-files",), ("claude.ai", "anthropic.com", "claude.com")),
    ("google-gemini", "business-systems", "generative-ai", "browser-based", 3, "Google Gemini", ("transfers-files",), ("gemini.google.com",)),
    # Remote access.
    # D03: the apex and www names are the vendors' marketing sites; they affiliate with the provider but assert no
    # remote-control activity. Other names under the domain remain service affiliation (activity still unobserved).
    ("teamviewer", "networking", "remote-access", "client-server", 4, "TeamViewer remote control",
     ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("teamviewer.com",), ("teamviewer.com", "www.teamviewer.com")),
    ("anydesk", "networking", "remote-access", "client-server", 4, "AnyDesk remote control",
     ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("anydesk.com", "net.anydesk.com"), ("anydesk.com", "www.anydesk.com")),
    # Commerce and reference.
    ("amazon", "general-internet", "internet-utility", "browser-based", 2, "Amazon retail site", ("widely-used",), ("amazon.com", "media-amazon.com", "ssl-images-amazon.com")),
    ("ebay", "general-internet", "internet-utility", "browser-based", 2, "eBay marketplace", (), ("ebay.com", "ebayimg.com", "ebaystatic.com")),
    ("paypal", "business-systems", "general-business", "browser-based", 2, "PayPal payments", ("widely-used",), ("paypal.com", "paypalobjects.com")),
    ("wikipedia", "general-internet", "internet-utility", "browser-based", 1, "Wikipedia and Wikimedia projects", ("widely-used",), ("wikipedia.org", "wikimedia.org")),
    # ---- Content release 2026.11.1: 115 more services, same rule (operator-owned domains only) ----
    # Video, audio and gaming.
    ("hbo-max", "media", "photo-video", "browser-based", 2, "Max (HBO Max) video streaming", ("excessive-bandwidth",), ("max.com", "hbomax.com")),
    ("paramount-plus", "media", "photo-video", "browser-based", 2, "Paramount+ video streaming", ("excessive-bandwidth",), ("paramountplus.com",)),
    ("peacock", "media", "photo-video", "browser-based", 2, "Peacock video streaming", ("excessive-bandwidth",), ("peacocktv.com",)),
    ("dailymotion", "media", "photo-video", "browser-based", 2, "Dailymotion video hosting", ("excessive-bandwidth", "transfers-files"), ("dailymotion.com", "dmcdn.net")),
    ("apple-tv", "media", "photo-video", "client-server", 2, "Apple TV+ video streaming", ("excessive-bandwidth",), ("tv.apple.com",)),
    ("apple-music", "media", "audio-streaming", "client-server", 2, "Apple Music streaming", ("excessive-bandwidth", "widely-used"), ("music.apple.com",)),
    ("soundcloud", "media", "audio-streaming", "browser-based", 2, "SoundCloud audio streaming", ("excessive-bandwidth", "transfers-files"), ("soundcloud.com", "sndcdn.com")),
    ("deezer", "media", "audio-streaming", "client-server", 2, "Deezer music streaming", ("excessive-bandwidth",), ("deezer.com", "dzcdn.net")),
    ("pandora", "media", "audio-streaming", "client-server", 2, "Pandora music streaming", ("excessive-bandwidth",), ("pandora.com",)),
    ("epic-games", "media", "gaming", "client-server", 3, "Epic Games store, launcher and Fortnite services",
     ("excessive-bandwidth", "transfers-files"), ("epicgames.com", "fortnite.com", "epicgames.dev")),
    ("roblox", "media", "gaming", "client-server", 3, "Roblox game platform", ("excessive-bandwidth", "widely-used"), ("roblox.com", "rbxcdn.com")),
    ("xbox-live", "media", "gaming", "client-server", 2, "Xbox network services", ("excessive-bandwidth", "widely-used"), ("xboxlive.com", "xbox.com")),
    ("playstation-network", "media", "gaming", "client-server", 2, "PlayStation Network services",
     ("excessive-bandwidth", "widely-used"), ("playstation.com", "playstation.net")),
    ("nintendo", "media", "gaming", "client-server", 2, "Nintendo online services", ("excessive-bandwidth",), ("nintendo.com", "nintendo.net")),
    ("ea-games", "media", "gaming", "client-server", 2, "Electronic Arts game services", ("excessive-bandwidth",), ("ea.com",)),
    ("battle-net", "media", "gaming", "client-server", 2, "Blizzard Battle.net game services", ("excessive-bandwidth",), ("battle.net", "blizzard.com")),
    ("riot-games", "media", "gaming", "client-server", 2, "Riot Games services", ("excessive-bandwidth",), ("riotgames.com", "leagueoflegends.com")),
    # Social networking.
    ("threads", "collaboration", "social-networking", "browser-based", 3, "Threads social network", ("transfers-files",), ("threads.net", "threads.com")),
    ("tumblr", "collaboration", "social-networking", "browser-based", 3, "Tumblr blogging platform", ("transfers-files",), ("tumblr.com",)),
    ("quora", "collaboration", "social-networking", "browser-based", 2, "Quora questions and answers", (), ("quora.com", "quoracdn.net")),
    ("vk", "collaboration", "social-networking", "browser-based", 3, "VK social network", ("transfers-files", "widely-used"), ("vk.com", "userapi.com")),
    ("bluesky", "collaboration", "social-networking", "browser-based", 3, "Bluesky social network", ("transfers-files",), ("bsky.app", "bsky.social")),
    ("weibo", "collaboration", "social-networking", "browser-based", 3, "Sina Weibo social network", ("transfers-files", "widely-used"), ("weibo.com", "weibo.cn")),
    # Messaging and meetings.
    ("facebook-messenger", "collaboration", "instant-messaging", "browser-based", 3, "Facebook Messenger", ("widely-used", "transfers-files"), ("messenger.com",)),
    ("line", "collaboration", "instant-messaging", "client-server", 3, "LINE messaging and calls", ("transfers-files", "widely-used"), ("line.me", "line-scdn.net")),
    ("wechat", "collaboration", "instant-messaging", "client-server", 3, "WeChat messaging", ("transfers-files", "widely-used"), ("wechat.com", "weixin.qq.com")),
    ("viber", "collaboration", "instant-messaging", "client-server", 3, "Viber messaging and calls", ("transfers-files",), ("viber.com",)),
    ("threema", "collaboration", "instant-messaging", "client-server", 3, "Threema encrypted messaging", ("transfers-files", "evasive"), ("threema.ch",)),
    ("matrix-element", "collaboration", "instant-messaging", "client-server", 3, "Matrix.org homeserver and Element client",
     ("transfers-files",), ("matrix.org", "element.io")),
    ("goto-meeting", "collaboration", "voip-video", "client-server", 2, "GoTo Meeting", ("excessive-bandwidth",), ("gotomeeting.com", "goto.com")),
    ("ringcentral", "collaboration", "voip-video", "client-server", 2, "RingCentral calls and meetings", (), ("ringcentral.com",)),
    # Email.
    ("yahoo-mail", "collaboration", "email", "browser-based", 2, "Yahoo Mail web mail", ("widely-used", "transfers-files"), ("mail.yahoo.com",)),
    ("proton-mail", "collaboration", "email", "browser-based", 2, "Proton Mail and Proton account services",
     ("transfers-files", "evasive"), ("proton.me", "protonmail.com", "protonmail.ch")),
    ("zoho", "business-systems", "office-programs", "browser-based", 2, "Zoho business applications and mail", ("transfers-files",), ("zoho.com", "zoho.eu")),
    # Storage and file transfer.
    ("mega", "general-internet", "file-sharing", "browser-based", 4, "MEGA encrypted file storage",
     ("transfers-files", "evasive", "prone-to-misuse"), ("mega.nz", "mega.io", "mega.co.nz")),
    ("wetransfer", "general-internet", "file-sharing", "browser-based", 3, "WeTransfer file transfer", ("transfers-files",), ("wetransfer.com", "wetransfer.net")),
    ("mediafire", "general-internet", "file-sharing", "browser-based", 4, "MediaFire file hosting", ("transfers-files", "prone-to-misuse"), ("mediafire.com",)),
    ("pcloud", "general-internet", "file-sharing", "client-server", 3, "pCloud file storage", ("transfers-files",), ("pcloud.com",)),
    ("pastebin", "general-internet", "file-sharing", "browser-based", 4, "Pastebin text sharing",
     ("transfers-files", "prone-to-misuse", "used-by-malware"), ("pastebin.com",)),
    # Office, design and business services.
    ("servicenow", "business-systems", "general-business", "browser-based", 2, "ServiceNow platform", (), ("servicenow.com", "service-now.com")),
    ("workday", "business-systems", "general-business", "browser-based", 2, "Workday HR and finance", (), ("workday.com", "myworkday.com")),
    ("hubspot", "business-systems", "general-business", "browser-based", 2, "HubSpot CRM", (), ("hubspot.com",)),
    ("zendesk", "business-systems", "general-business", "browser-based", 2, "Zendesk customer service", ("transfers-files",), ("zendesk.com", "zdassets.com")),
    ("docusign", "business-systems", "general-business", "browser-based", 2, "DocuSign e-signature", ("transfers-files",), ("docusign.com", "docusign.net")),
    ("stripe", "business-systems", "general-business", "browser-based", 2, "Stripe payments", ("widely-used",), ("stripe.com", "stripe.network")),
    ("coinbase", "business-systems", "general-business", "browser-based", 3, "Coinbase cryptocurrency exchange", (), ("coinbase.com",)),
    ("binance", "business-systems", "general-business", "browser-based", 3, "Binance cryptocurrency exchange", (), ("binance.com",)),
    ("adobe-cloud", "business-systems", "office-programs", "client-server", 2, "Adobe Creative Cloud and account services",
     ("transfers-files", "widely-used"), ("adobe.com", "adobelogin.com", "adobe.io")),
    ("canva", "business-systems", "office-programs", "browser-based", 2, "Canva design", ("transfers-files",), ("canva.com",)),
    ("figma", "business-systems", "office-programs", "browser-based", 2, "Figma design", ("transfers-files",), ("figma.com",)),
    ("miro", "business-systems", "office-programs", "browser-based", 2, "Miro whiteboard", ("transfers-files",), ("miro.com",)),
    ("trello", "business-systems", "office-programs", "browser-based", 2, "Trello boards", ("transfers-files",), ("trello.com",)),
    ("asana", "business-systems", "office-programs", "browser-based", 2, "Asana work management", ("transfers-files",), ("asana.com",)),
    ("monday", "business-systems", "office-programs", "browser-based", 2, "monday.com work management", ("transfers-files",), ("monday.com",)),
    ("airtable", "business-systems", "office-programs", "browser-based", 2, "Airtable databases", ("transfers-files",), ("airtable.com",)),
    ("evernote", "business-systems", "office-programs", "client-server", 2, "Evernote notes", ("transfers-files",), ("evernote.com",)),
    ("grammarly", "business-systems", "office-programs", "browser-based", 3, "Grammarly writing assistant", ("pervasive",), ("grammarly.com", "grammarly.io")),
    # Software development and delivery.
    ("docker-hub", "business-systems", "software-development", "client-server", 2, "Docker Hub and registry", ("transfers-files",), ("docker.com", "docker.io")),
    ("npm", "business-systems", "software-development", "client-server", 2, "npm package registry", ("transfers-files",), ("npmjs.com", "npmjs.org")),
    ("pypi", "business-systems", "software-development", "client-server", 2, "Python Package Index", ("transfers-files",), ("pypi.org", "pythonhosted.org")),
    ("stack-overflow", "business-systems", "software-development", "browser-based", 1, "Stack Overflow and Stack Exchange",
     ("widely-used",), ("stackoverflow.com", "stackexchange.com", "sstatic.net")),
    ("jetbrains", "business-systems", "software-development", "client-server", 1, "JetBrains tools and account services", ("transfers-files",), ("jetbrains.com",)),
    ("apple-app-store", "business-systems", "software-development", "client-server", 1, "Apple App Store and iTunes Store",
     ("widely-used", "transfers-files"), ("apps.apple.com", "itunes.apple.com")),
    ("google-play", "business-systems", "software-development", "client-server", 1, "Google Play store",
     ("widely-used", "transfers-files"), ("play.google.com", "play.googleapis.com")),
    # Identity and password managers.
    ("okta", "business-systems", "auth-service", "browser-based", 1, "Okta sign-in", ("widely-used",), ("okta.com", "oktacdn.com", "oktapreview.com")),
    ("duo-security", "business-systems", "auth-service", "client-server", 1, "Cisco Duo multi-factor authentication", (), ("duosecurity.com",)),
    ("auth0", "business-systems", "auth-service", "browser-based", 1, "Auth0 sign-in", (), ("auth0.com",)),
    ("google-accounts", "business-systems", "auth-service", "browser-based", 1, "Google account sign-in", ("widely-used",), ("accounts.google.com",)),
    ("1password", "business-systems", "auth-service", "client-server", 2, "1Password password manager", (), ("1password.com", "1password.eu")),
    ("lastpass", "business-systems", "auth-service", "client-server", 2, "LastPass password manager", (), ("lastpass.com",)),
    ("bitwarden", "business-systems", "auth-service", "client-server", 2, "Bitwarden password manager", (), ("bitwarden.com",)),
    # Generative AI.
    ("ms-copilot", "business-systems", "generative-ai", "browser-based", 3, "Microsoft Copilot", ("transfers-files",), ("copilot.microsoft.com",)),
    ("github-copilot", "business-systems", "generative-ai", "client-server", 3, "GitHub Copilot", ("transfers-files",), ("githubcopilot.com",)),
    ("perplexity", "business-systems", "generative-ai", "browser-based", 3, "Perplexity AI", ("transfers-files",), ("perplexity.ai",)),
    ("mistral-ai", "business-systems", "generative-ai", "browser-based", 3, "Mistral AI", ("transfers-files",), ("mistral.ai",)),
    ("deepseek", "business-systems", "generative-ai", "browser-based", 3, "DeepSeek", ("transfers-files",), ("deepseek.com",)),
    ("xai-grok", "business-systems", "generative-ai", "browser-based", 3, "xAI Grok", ("transfers-files",), ("grok.com", "x.ai")),
    ("hugging-face", "business-systems", "generative-ai", "client-server", 3, "Hugging Face models and datasets", ("transfers-files",), ("huggingface.co", "hf.co")),
    ("midjourney", "business-systems", "generative-ai", "browser-based", 3, "Midjourney image generation", ("transfers-files",), ("midjourney.com",)),
    ("character-ai", "business-systems", "generative-ai", "browser-based", 3, "Character.AI", (), ("character.ai",)),
    ("poe", "business-systems", "generative-ai", "browser-based", 3, "Quora Poe", ("transfers-files",), ("poe.com",)),
    # Remote access (apex and www are the vendors' marketing sites, as for TeamViewer and AnyDesk).
    ("logmein", "networking", "remote-access", "client-server", 4, "LogMeIn remote access",
     ("tunnels-other-applications", "prone-to-misuse"), ("logmein.com", "logmeininc.com"), ("logmein.com", "www.logmein.com")),
    ("splashtop", "networking", "remote-access", "client-server", 4, "Splashtop remote access",
     ("tunnels-other-applications", "prone-to-misuse"), ("splashtop.com",), ("splashtop.com", "www.splashtop.com")),
    ("rustdesk", "networking", "remote-access", "client-server", 4, "RustDesk remote control (public servers)",
     ("tunnels-other-applications", "prone-to-misuse", "used-by-malware"), ("rustdesk.com",), ("rustdesk.com", "www.rustdesk.com")),
    ("chrome-remote-desktop", "networking", "remote-access", "browser-based", 4, "Chrome Remote Desktop",
     ("tunnels-other-applications", "prone-to-misuse"), ("remotedesktop.google.com",)),
    # VPN and overlay networks (apex and www are marketing sites).
    ("nordvpn", "networking", "encrypted-tunnel", "client-server", 4, "NordVPN",
     ("tunnels-other-applications", "evasive"), ("nordvpn.com", "nordcdn.com"), ("nordvpn.com", "www.nordvpn.com")),
    ("expressvpn", "networking", "encrypted-tunnel", "client-server", 4, "ExpressVPN",
     ("tunnels-other-applications", "evasive"), ("expressvpn.com",), ("expressvpn.com", "www.expressvpn.com")),
    ("proton-vpn", "networking", "encrypted-tunnel", "client-server", 4, "Proton VPN",
     ("tunnels-other-applications", "evasive"), ("protonvpn.com", "protonvpn.net", "protonvpn.ch"), ("protonvpn.com", "www.protonvpn.com")),
    ("surfshark", "networking", "encrypted-tunnel", "client-server", 4, "Surfshark VPN",
     ("tunnels-other-applications", "evasive"), ("surfshark.com",), ("surfshark.com", "www.surfshark.com")),
    ("mullvad", "networking", "encrypted-tunnel", "client-server", 4, "Mullvad VPN",
     ("tunnels-other-applications", "evasive"), ("mullvad.net",), ("mullvad.net", "www.mullvad.net")),
    ("tailscale", "networking", "encrypted-tunnel", "client-server", 3, "Tailscale coordination and relay servers",
     ("tunnels-other-applications",), ("tailscale.com", "tailscale.io"), ("tailscale.com", "www.tailscale.com")),
    ("zerotier", "networking", "encrypted-tunnel", "client-server", 3, "ZeroTier controller services",
     ("tunnels-other-applications",), ("zerotier.com",), ("zerotier.com", "www.zerotier.com")),
    # Encrypted DNS resolvers (the server name of a DoH/DoT/DoQ session).
    ("cloudflare-dns", "networking", "infrastructure", "client-server", 3, "Cloudflare public DNS resolver (1.1.1.1)",
     ("evasive",), ("cloudflare-dns.com", "one.one.one.one")),
    ("google-public-dns", "networking", "infrastructure", "client-server", 3, "Google Public DNS resolver", ("evasive",), ("dns.google",)),
    ("quad9-dns", "networking", "infrastructure", "client-server", 3, "Quad9 public DNS resolver", ("evasive",), ("quad9.net",)),
    ("nextdns", "networking", "infrastructure", "client-server", 3, "NextDNS resolver", ("evasive",), ("nextdns.io",)),
    ("adguard-dns", "networking", "infrastructure", "client-server", 3, "AdGuard DNS resolver", ("evasive",), ("adguard-dns.com", "dns.adguard.com")),
    # Platform bases (names not mapped to a more specific application, like google-base).
    ("apple-base", "general-internet", "internet-utility", "client-server", 2, "Apple services not mapped to a more specific application",
     ("widely-used", "pervasive"), ("apple.com", "cdn-apple.com", "mzstatic.com")),
    ("apple-push", "general-internet", "internet-utility", "client-server", 1, "Apple Push Notification service", ("widely-used", "pervasive"), ("push.apple.com",)),
    ("ms-base", "general-internet", "internet-utility", "client-server", 2, "Microsoft services not mapped to a more specific application",
     ("widely-used", "pervasive"), ("microsoft.com", "msn.com", "windows.com", "live.com")),
    ("yahoo", "general-internet", "internet-utility", "browser-based", 2, "Yahoo portal and search", ("widely-used",), ("yahoo.com", "yimg.com")),
    # Search, advertising and measurement.
    ("bing", "general-internet", "internet-utility", "browser-based", 2, "Microsoft Bing search", ("widely-used",), ("bing.com", "bing.net")),
    ("duckduckgo", "general-internet", "internet-utility", "browser-based", 1, "DuckDuckGo search", (), ("duckduckgo.com",)),
    ("baidu", "general-internet", "internet-utility", "browser-based", 2, "Baidu search", ("widely-used",), ("baidu.com", "bdstatic.com")),
    ("yandex", "general-internet", "internet-utility", "browser-based", 2, "Yandex search and services", ("widely-used",), ("yandex.ru", "yandex.com", "yandex.net")),
    ("google-ads", "general-internet", "internet-utility", "browser-based", 2, "Google advertising",
     ("pervasive", "widely-used"), ("doubleclick.net", "googlesyndication.com", "googleadservices.com")),
    ("google-analytics", "general-internet", "internet-utility", "browser-based", 2, "Google Analytics and Tag Manager",
     ("pervasive", "widely-used"), ("google-analytics.com", "googletagmanager.com")),
    ("speedtest", "general-internet", "internet-utility", "client-server", 2, "Ookla Speedtest", ("excessive-bandwidth",), ("speedtest.net", "ooklaserver.net")),
    # Commerce and travel.
    ("aliexpress", "general-internet", "internet-utility", "browser-based", 2, "AliExpress marketplace", ("widely-used",), ("aliexpress.com", "aliexpress.us")),
    ("walmart", "general-internet", "internet-utility", "browser-based", 2, "Walmart retail site", (), ("walmart.com", "walmartimages.com")),
    ("etsy", "general-internet", "internet-utility", "browser-based", 2, "Etsy marketplace", (), ("etsy.com", "etsystatic.com")),
    ("shopify", "business-systems", "general-business", "browser-based", 2, "Shopify merchant administration", (), ("shopify.com",)),
    ("booking", "general-internet", "internet-utility", "browser-based", 2, "Booking.com travel", (), ("booking.com", "bstatic.com")),
    ("airbnb", "general-internet", "internet-utility", "browser-based", 2, "Airbnb rentals", (), ("airbnb.com", "muscache.com")),
    ("uber", "general-internet", "internet-utility", "client-server", 2, "Uber rides and delivery", (), ("uber.com",)),
)

# An entry is (name, category, subcategory, technology, risk, description, characteristics, domains[, web_fronts]).
# `domains` affiliate a server name with the provider's service; `web_fronts` are exact names of the provider's
# public web presence (marketing, documentation): they affiliate with the provider but never assert that the
# service's application traffic was observed (D03). A web front wins over the domain it sits in.
_APP_DOMAINS, _WEB_FRONTS, _SUFFIXES = {}, {}, {}
APP_DOMAINS = MappingProxyType(_APP_DOMAINS)
WEB_FRONTS = MappingProxyType(_WEB_FRONTS)
HOST_SUFFIXES = MappingProxyType(_SUFFIXES)


def build_tables(entries):
    """(app_domains, web_fronts, suffixes) for catalog entries given as tuples or dicts; duplicates are errors."""
    domains, fronts, suffixes = {}, {}, {}
    for entry in entries:
        if isinstance(entry, dict):
            name, entry_domains, entry_fronts = entry["name"], entry["domains"], entry.get("web_fronts", ())
        else:
            name, entry_domains, entry_fronts = entry[0], entry[7], entry[8] if len(entry) > 8 else ()
        if name in domains:
            raise ValueError("Duplicate host-catalog entry " + name)
        domains[name] = tuple(entry_domains)
        for front in entry_fronts:
            if front in fronts:
                raise ValueError("Duplicate host-catalog web front " + front)
            fronts[front] = name
        for domain in entry_domains:
            if domain in suffixes:
                raise ValueError("Duplicate host-catalog domain " + domain)
            suffixes[domain] = name
    return domains, fronts, suffixes


def rebuild(entries):
    """D08: run the lookup tables from another release's entries (content.select); the proxies above follow."""
    domains, fronts, suffixes = build_tables(entries)
    for table, values in ((_APP_DOMAINS, domains), (_WEB_FRONTS, fronts), (_SUFFIXES, suffixes)):
        table.clear()
        table.update(values)


rebuild(_HOST_APPS)
KINDS = ("service", "provider-web")


def catalog_entries(make):
    """Application entries for applications.py, built with its `_app` constructor."""
    return tuple(make(entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6],
                      implicitly_uses=("ssl", "web-browsing"))
                 for entry in _HOST_APPS)


def attribution_for_host(hostname):
    """(provider, kind) for a normalized server name, or None.

    kind is "provider-web" for an exact web-front name and "service" for a name under a service domain
    (longest label-boundary suffix). Shared hosting and tenant domains are deliberately absent, so an
    unknown tenant or subdomain yields None rather than an affiliation it does not have.
    """
    provider = WEB_FRONTS.get(hostname)
    if provider is not None:
        return provider, "provider-web"
    position = 0
    while True:
        name = HOST_SUFFIXES.get(hostname[position:])
        if name is not None:
            return name, "service"
        dot = hostname.find(".", position)
        if dot < 0:
            return None
        position = dot + 1


def application_for_host(hostname):
    """Catalog application whose service a normalized server name affiliates with, or None.

    A provider's web front returns None here: it names the provider (see attribution_for_host), not an
    application whose activity was observed.
    """
    found = attribution_for_host(hostname)
    return found[0] if found is not None and found[1] == "service" else None
