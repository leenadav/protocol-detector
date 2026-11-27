# Quality filter: 1,696 catalog proposals (PRO-491 part A)

Method: each entry (name, official domain, current category, source note) classified by claude-sonnet-5-5 through one Message Batch (+ one retry batch for 252 requests cut off by the token limit), with the PRO-498 40-row calibration set in the prompt. **Model judgement from names and domains; no per-entry web check or liveness test** (DNS resolution was already checked when the batches were built). Treat `low` confidence rows as a review queue. Machine-readable result: `classification.json`; scripts in `scripts/`.

Pack vocabulary = the 25 category/subcategory pairs in pack.json 2026.11.9. Nothing in the pack changes.

## Headline

| verdict | n | % |
|---|---|---|
| keep | 255 | 15.0% |
| fix | 267 | 15.7% |
| drop | 1174 | 69.2% |
| total | 1696 | |

## Drops by reason

| reason | n |
|---|---|
| gaming_publisher_page | 614 |
| news_content_site | 240 |
| offline_or_selfhosted_software | 176 |
| dead_or_defunct | 64 |
| non_application | 49 |
| marketing_page | 26 |
| other | 5 |

## By batch

| batch | keep | fix | drop | unparsed |
|---|---|---|---|---|
| 1 | 61 | 77 | 162 | 0 |
| 2 | 59 | 74 | 167 | 0 |
| 3 | 34 | 34 | 103 | 0 |
| 4 | 32 | 2 | 266 | 0 |
| 5 | 32 | 0 | 268 | 0 |
| 6 | 12 | 1 | 156 | 0 |
| 7 | 25 | 79 | 52 | 0 |

## Confidence

high: 813, medium: 845, low: 38


## Fix targets (new category)

| target | n |
|---|---|
| business-systems/general-business | 55 |
| collaboration/social-networking | 51 |
| media/photo-video | 36 |
| general-internet/internet-utility | 30 |
| media/audio-streaming | 17 |
| general-internet/file-sharing | 15 |
| business-systems/generative-ai | 9 |
| business-systems/software-development | 9 |
| media/gaming | 9 |
| collaboration/voip-video | 8 |
| business-systems/office-programs | 7 |
| collaboration/instant-messaging | 6 |
| business-systems/database | 5 |
| collaboration/email | 4 |
| networking/infrastructure | 2 |
| business-systems/management | 2 |
| networking/encrypted-tunnel | 1 |
| business-systems/storage-backup | 1 |

## 30 sample rows: keep (random.seed(491))

| name | domain | current | new | reason | conf |
|---|---|---|---|---|---|
| twinkl | twinkl.co.uk | general-internet/internet-utility |  | Twinkl is an online educational resource subscription service with its own web servers; category acceptable. | medium |
| decentraland | decentraland.org | media/gaming |  | Decentraland is a live virtual world platform with its own servers, content, and marketplace calling decentraland.org domains; not just a publisher page. | medium |
| medrxiv | medrxiv.org | general-internet/internet-utility |  | medRxiv is an online preprint server for health sciences, a real web service on its own domain; category internet-utility is acceptable (like sci-hub). | medium |
| biolib | biolib.cz | business-systems/database |  | Czech online biological database (taxa, images, literature) served from its own biolib.cz servers; database category fits. | medium |
| freechess | freechess.org | media/gaming |  | Free Internet Chess Server (FICS) is a live online chess service running on its own servers; media/gaming fits. | medium |
| diep | diep.io | media/gaming |  | Diep.io is a live browser multiplayer game whose traffic goes to its own game servers on diep.io. | high |
| bethesda | bethesda.net | media/gaming |  | bethesda.net runs its own services: account login, in-game mod hosting (Creation Club) and Fallout 76 backend, beyond marketing pages. | medium |
| erepublik | erepublik.com | media/gaming |  | Erepublik is a browser-based online multiplayer strategy game running on its own servers at erepublik.com; gaming category is correct. | high |
| douyin | douyin.com | collaboration/social-networking |  | Douyin is ByteDance's Chinese short-video social platform, calling its own servers on douyin.com; the social-networking category is acceptable. | high |
| filmportal | filmportal.de | business-systems/database |  | Online film database web service run by the German Film Institute; traffic goes to its own servers. | medium |
| mewe | mewe.com | collaboration/social-networking |  | MeWe is a real social networking service operating its own servers on mewe.com; the category is already correct. | high |
| wikirank | wikirank.net | general-internet/internet-utility |  | Real web service ranking Wikipedia article quality/popularity from its own servers; internet-utility category is acceptable. | medium |
| observation | observation.org | business-systems/database |  | Observation.org is an online biodiversity observation database/platform where users submit sightings via its own web service and apps. | high |
| playism | playism.com | media/gaming |  | Playism runs an indie game digital storefront and download service on playism.com, not just a publisher marketing page. | medium |
| minds | minds.com | collaboration/social-networking |  | Minds is an open-source social network operating its own web service at minds.com; the category is correct. | high |
| geonames | geonames.org | business-systems/database |  | GeoNames is an online geographical database with web services and API on geonames.org; database category fits. | high |
| farmerama | farmerama.com | media/gaming |  | Farmerama is a browser-based farming game that runs on its own servers at farmerama.com; media/gaming is correct. | medium |
| championsofregnum | championsofregnum.com | media/gaming |  | Champions of Regnum is a live MMORPG with its own client, accounts and servers on this domain. | medium |
| tagged | tagged.com | collaboration/social-networking |  | Tagged is a social network that calls its own servers on tagged.com. The category is correct, but I'm unsure the service is still running. | medium |
| urbandictionary | urbandictionary.com | general-internet/internet-utility |  | Urban Dictionary is a live crowd-sourced online dictionary web service on its own domain; internet-utility category is reasonable. | medium |
| mixi | mixi.jp | collaboration/social-networking |  | Mixi is a live Japanese social networking service operating on mixi.jp; category social-networking is correct. | high |
| king | king.com | media/gaming |  | King's games (Candy Crush etc.) call its own servers on king.com, so traffic isn't just a marketing page. | medium |
| meetup | meetup.com | collaboration/social-networking |  | Meetup is a real web service and app for organizing events and groups; social-networking category fits. | high |
| w3schools | w3schools.com | general-internet/internet-utility |  | Real web service with interactive editors, accounts, and certifications on its own domain; the current category is acceptable. | medium |
| plemiona | plemiona.pl | media/gaming |  | Plemiona is the Polish Tribal Wars browser MMO; gameplay runs on plemiona.pl world subdomains, so it is a live game with its own servers. | high |
| neo4j-com | neo4j.com | business-systems/database |  | Neo4j is a graph database vendor with cloud services (Aura), downloads, and update/licensing servers on neo4j.com; database category fits. | high |
| familysearch | familysearch.org | business-systems/database |  | FamilySearch is an online genealogy database service operating on its own servers at familysearch.org; database category fits. | high |
| parallels | parallels.com | business-systems/general-business |  | Parallels Desktop client contacts vendor servers for licensing, updates, and Parallels Access/cloud services on parallels.com. | medium |
| mailfence | mailfence.com | collaboration/email |  | Mailfence is a secure email SaaS service operating its own servers on mailfence.com; the email category is correct. | high |
| lunascape | lunascape.org | general-internet/internet-utility |  | Web browser client that contacts vendor servers for updates, sync and search portal; the category is acceptable. | medium |

## 30 sample rows: fix (random.seed(491))

| name | domain | current | new | reason | conf |
|---|---|---|---|---|---|
| stradivarius | stradivarius.com | general-internet/internet-utility | business-systems/general-business | Stradivarius is a fashion retailer with an e-commerce site and app on its own domain; it is a real web service, but the category is wrong. | medium |
| memoq | memoq.com | business-systems/software-development | business-systems/office-programs | Translation management tool with desktop client and cloud servers (licensing, memoQ TMS); not software-development. Productivity/office category fits better. | medium |
| similarweb | similarweb.com | general-internet/internet-utility | business-systems/general-business | Similarweb is a SaaS web analytics and market intelligence platform; it fits business-systems/general-business better than internet-utility. | medium |
| digikala | digikala.com | general-internet/internet-utility | business-systems/general-business | Digikala is a major Iranian e-commerce marketplace with its own web service and apps; internet-utility is wrong category. | medium |
| hily | hily.com | business-systems/software-development | collaboration/social-networking | Hily is a dating app/service with its own servers; the software-development category is wrong, so it belongs under social networking. | high |
| apertium | apertium.org | business-systems/general-business | general-internet/internet-utility | Open-source machine translation project with a live web translator and API on apertium.org; a utility, not general business. | medium |
| mineplex | mineplex.com | business-systems/general-business | media/gaming | Minecraft multiplayer server network with its own game servers on mineplex.com; category should be gaming, not general-business. | medium |
| wikitree | wikitree.com | business-systems/database | collaboration/social-networking | Real collaborative genealogy web service with user profiles and community; social-networking fits better than generic database. | medium |
| freecodecamp | freecodecamp.org | general-internet/internet-utility | business-systems/software-development | freeCodeCamp is a real web learning platform with its own servers; category should be software-development rather than internet-utility. | medium |
| gaiaonline | gaiaonline.com | general-internet/internet-utility | collaboration/social-networking | Live anime social virtual world/forum site with own servers; category should be social networking, not internet utility. | medium |
| brilliant | brilliant.org | general-internet/internet-utility | business-systems/general-business | Brilliant.org is an online interactive learning platform (SaaS); real service, but not an internet utility. Closest fit is general-business. | low |
| last | last.fm | collaboration/social-networking | media/audio-streaming | Last.fm is a music streaming/scrobbling service with its own servers; audio streaming fits better than social networking. | medium |
| ankiweb | ankiweb.net | business-systems/software-development | business-systems/general-business | AnkiWeb is a real sync/web service for Anki flashcards; software-development category is wrong, general-business fits best. | medium |
| virtualdj | virtualdj.com | business-systems/general-business | media/audio-streaming | Desktop DJ client calling vendor servers for licensing, updates and online content streaming; audio category fits better than general-business. | medium |
| bittorrent-com | bittorrent.com | business-systems/software-development | general-internet/file-sharing | BitTorrent client/company calls own servers for updates and services; it is file-sharing, not software development. | high |
| odysee | odysee.com | media/audio-streaming | media/photo-video | Odysee is a video-sharing platform on LBRY with its own servers; video streaming, not audio streaming. | high |
| watchmojo | watchmojo.com | general-internet/internet-utility | media/photo-video | Video content site with its own servers and streaming; media/photo-video fits better than internet-utility. | medium |
| didiglobal | didiglobal.com | business-systems/software-development | business-systems/general-business | DiDi is a ride-hailing service with its own servers; the corporate domain suits a general-business or internet-utility label, not software-development. | medium |
| mixcloud | mixcloud.com | general-internet/internet-utility | media/audio-streaming | Mixcloud is an online audio streaming service for DJ mixes and radio shows; it belongs under audio-streaming, not internet-utility. | high |
| librivox | librivox.org | general-internet/internet-utility | media/audio-streaming | LibriVox is a real web service distributing free public-domain audiobooks; audio-streaming fits better than internet-utility. | medium |
| wikiversity | wikiversity.org | business-systems/general-business | general-internet/internet-utility | Live Wikimedia wiki service on its own domain; general-business is wrong, internet-utility fits better. | medium |
| limewire | limewire.com | business-systems/software-development | general-internet/file-sharing | LimeWire is now a live file-sharing/content platform at limewire.com (relaunched 2022), not software development; category should be file-sharing. | high |
| quakenet | quakenet.org | general-internet/internet-utility | collaboration/instant-messaging | QuakeNet is an IRC chat network with its own servers; belongs in instant-messaging, not internet-utility. | high |
| linguee | linguee.com | business-systems/database | general-internet/internet-utility | Linguee is an online dictionary/translation search service on its own servers; database category is wrong, closest fit is internet-utility. | medium |
| manus | manus.im | business-systems/software-development | business-systems/generative-ai | Manus is a web-based AI agent SaaS; generative-ai fits better than software-development. | high |
| blued | blued.cn | business-systems/general-business | collaboration/social-networking | Blued is a Chinese LGBTQ social networking and live-streaming app with its own servers; category should be social networking. | high |
| nofap | nofap.com | general-internet/internet-utility | collaboration/social-networking | NoFap is a real community/forum web service with its own servers; social-networking fits better than internet-utility. | medium |
| wikifunctions | wikifunctions.org | business-systems/general-business | general-internet/internet-utility | Wikifunctions is a live Wikimedia web service (wiki of functions); general-business is wrong, internet-utility fits better. | medium |
| kyliecosmetics | kyliecosmetics.com | general-internet/internet-utility | business-systems/general-business | Online retail store with real transactions on own domain; not an internet utility. Closest vocabulary fit is general-business. | low |
| postcrossing | postcrossing.com | general-internet/internet-utility | collaboration/social-networking | Real web service for postcard exchange among users; community/social platform, not an internet utility. | medium |

## 30 sample rows: drop (random.seed(491))

| name | domain | current | new | reason | conf |
|---|---|---|---|---|---|
| giantsparrow | giantsparrow.com | media/gaming |  | Giant Sparrow is a game studio (What Remains of Edith Finch); the site is a marketing page, not a service with its own servers. | high |
| transportfever2 | transportfever2.com | media/gaming |  | Transport Fever 2 is an offline single-player game; the official site is marketing, and game traffic goes to Steam, not this domain. | medium |
| tampabay | tampabay.com | general-internet/internet-utility |  | Tampa Bay Times is a newspaper website; content-only news site, not an application service. | high |
| lsjbot | lsjbot.se | business-systems/general-business |  | Lsjbot is a Wikipedia article-creating bot by Sverker Johansson; not a network service with its own application traffic. | high |
| playdead | playdead.com | media/gaming |  | Playdead is a game studio (Limbo, Inside); its website is marketing, and game traffic goes to platform servers like Steam. | high |
| superhexagon | superhexagon.com | media/gaming |  | Super Hexagon is an offline indie game by Terry Cavanagh; superhexagon.com is a marketing page, gameplay runs via Steam or app stores. | high |
| deltarune | deltarune.com | media/gaming |  | deltarune.com is Toby Fox's game marketing/info site; the game is an offline purchase, so any match would only be a site visit. | high |
| painterartist | painterartist.com | business-systems/general-business |  | Corel Painter is a desktop digital painting application; the domain is a product website, with no significant vendor service traffic. | medium |
| blic | blic.rs | general-internet/internet-utility |  | Blic is a Serbian daily newspaper; blic.rs is a news content website, not an application service. | high |
| croteam | croteam.com | media/gaming |  | Croteam is a game studio (Serious Sam, Talos Principle); croteam.com is a studio site, and game traffic goes to platform or game servers. | high |
| silenthunteriii | silenthunteriii.com | media/gaming |  | Silent Hunter III is an offline Ubisoft submarine sim; the domain is a publisher/marketing page, with no game servers in the traffic path. | high |
| megacatstudios | megacatstudios.com | media/gaming |  | Megacat Studios is a game publisher/studio website; game traffic goes to platform or game servers, so a match would only be a marketing visit. | high |
| playdeadlock | playdeadlock.com | media/gaming |  | Deadlock is Valve's game; playdeadlock.com is a marketing/official site, while game traffic goes to Steam and Valve servers. | medium |
| twopointstudios | twopointstudios.com | media/gaming |  | Two Point Studios is a game developer/publisher; its site is marketing, and game traffic goes to platform or game servers. | high |
| ogre3d | ogre3d.org | media/gaming |  | OGRE3D is an open-source 3D rendering engine library, not a network service; the site is a project page, not a game publisher. | high |
| funkin | funkin.me | media/gaming |  | Funkin' is an offline/browser rhythm game; funkin.me is a publisher/landing page, with game traffic going to itch.io/Newgrounds. | medium |
| picnik | picnik.com | general-internet/internet-utility |  | Picnik was an online photo editor shut down by Google in April 2012; domain no longer serves it. | high |
| rephial | rephial.org | media/gaming |  | Rephial/Angband is a free offline roguelike; rephial.org is a download/community site, with no game servers in the traffic path. | high |
| morpheus | morpheus.com | business-systems/storage-backup |  | Morpheus is most likely the defunct 2000s P2P file-sharing client, and the domain no longer serves an app. The storage-backup category is wrong either way. | low |
| gpg4win | gpg4win.org | business-systems/general-business |  | Gpg4win is an offline Windows encryption software suite; the domain is a project/download site with no vendor service in the traffic path. | high |
| wikiba | wikiba.se | business-systems/database |  | Wikibase is self-hosted open-source software; wikiba.se is just the project website, with no vendor service in the traffic path. | medium |
| blueprincegame | blueprincegame.com | media/gaming |  | Blue Prince game publisher/official site; gameplay traffic goes to platform servers, so a match would only be a marketing page visit. | medium |
| headupgames | headupgames.com | media/gaming |  | Headup Games is a game publisher; its site is marketing, and game traffic goes to platforms like Steam. | high |
| unicode | unicode.org | business-systems/general-business |  | The Unicode Standard is a character encoding specification, not a network application; unicode.org is a standards body website. | high |
| coffeetalk | coffeetalk.info | media/gaming |  | Coffee Talk is a visual novel game; coffeetalk.info is a marketing site, and gameplay traffic goes to platforms like Steam. | medium |
| replaystudios | replaystudios.de | media/gaming |  | Game publisher/studio website; game traffic goes to platform or game servers, so a domain match would only be a marketing site visit. | medium |
| mediamolecule | mediamolecule.com | media/gaming |  | Media Molecule is a game studio (Dreams, LittleBigPlanet); its site is marketing, game traffic goes to PlayStation servers. | high |
| stepmania | stepmania.com | media/gaming |  | StepMania is open-source offline rhythm game software; stepmania.com is a project website, so a match would only be a website visit. | medium |
| tribesascend | tribesascend.com | media/gaming |  | Tribes: Ascend is a defunct Hi-Rez game; its official site is a publisher/marketing page and traffic goes to Steam or Hi-Rez servers. | medium |
| brothersthegame | brothersthegame.com | media/gaming |  | Brothers: A Tale of Two Sons is an offline single-player game; the domain is a publisher marketing page with no game servers. | medium |

## Open decision for Lee
`news_content_site` (240 drops, 14% of all entries) follows the PRO-498 calibration "rule gap": news and content-only sites are dropped as non-applications (a match would only be a website visit). If Lee keeps them as services, those 240 move to keep. Gaming publisher pages (614) are dropped by the same rule as calibration rows 18-34.

## Raw artifacts

`quality/out/` (entries.json, batch ids, retry ids, batch results) is not committed. It holds the Message Batch inputs and ids used for the classification; `classification.json` is the committed result. `scripts/classify_report.py` reads `out/` if you regenerate.
