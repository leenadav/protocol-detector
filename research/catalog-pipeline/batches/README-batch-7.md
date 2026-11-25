# Batch 7 (software that was kept), PRO-406

`batch-7-software.json`: 156 entries in the `pack.json` record format, with evidence. `batch-7-software-filter.jsonl`: all 805 software_project rows of the main proposal list with their outcome and reason. Input for the PRO-411 tool; the shipped pack is untouched. Built by `tools/make_software_batch.py`.

## Filter outcome (rule 2: keep services, SaaS and clients that talk to their own servers)
| outcome | n |
|---|---|
| dropped:classification_unsure | 28 |
| dropped:domain_does_not_resolve | 9 |
| dropped:not_a_network_service | 612 |
| kept | 156 |

The verdicts come from one claude-haiku-5-5 pass over each row's name and domain (Message Batches API, 2026-11-25), not from reading the projects. Some kept rows are self-hosted software with a vendor service (for example roundcube); treat the kept list as a first pass and review the 20 samples below. UNSURE rows are dropped, not guessed. Entry checks: domain in `source_note`, resolves, no clash with the shipped 544 apps and 442 host entries, unique names and domains. Defaults as in the other batches (risk 2, browser-based). Content QA not run.

## 20 sample rows (random.seed(413))
| # | name | domain | category/subcategory | model reason |
|---|---|---|---|---|
| 1 | IOTA (`iota`) | iota.org | business-systems/software-development | IOTA is a distributed ledger network with hosted nodes and services |
| 2 | ownCloud (`owncloud`) | owncloud.com | general-internet/internet-utility | ownCloud offers hosted cloud storage and sync services with vendor servers |
| 3 | Tron (`tron`) | tron.network | business-systems/software-development | Tron blockchain network; public nodes and hosted APIs |
| 4 | OnlyOffice (`onlyoffice`) | onlyoffice.com | business-systems/office-programs | Hosted office suite with cloud/SaaS offering and vendor servers |
| 5 | OsmAnd (`osmand`) | osmand.net | business-systems/software-development | Mobile navigation app syncing and tiles from osmand.net servers |
| 6 | /e/OS (`e`) | e.foundation | business-systems/software-development | Mobile OS with cloud services and app store contacting e.foundation servers |
| 7 | Jami (`jami`) | jami.net | business-systems/software-development | Jami is a messaging client using distributed network, not vendor servers |
| 8 | MAPS.ME (`maps`) | maps.me | business-systems/software-development | Mobile maps app syncing data and updates from its own servers |
| 9 | TrueCaller (`truecaller`) | truecaller.com | general-internet/internet-utility | Mobile caller ID app querying Truecaller's cloud servers |
| 10 | Pi-hole (`pi-hole`) | pi-hole.net | business-systems/software-development | Network-wide DNS sinkhole; its update and telemetry traffic hits pi-hole.net servers |
| 11 | Gitea (`gitea`) | gitea.com | business-systems/software-development | Self-hosted Git server; gitea.com hosts a public instance |
| 12 | Pocket (`getpocket`) | getpocket.com | general-internet/internet-utility | Read-later SaaS with apps syncing to getpocket.com servers |
| 13 | climateprediction.net (`climateprediction`) | climateprediction.net | business-systems/software-development | Volunteer distributed computing project; client talks to its own servers |
| 14 | Echolink (`echolink`) | echolink.org | business-systems/software-development | EchoLink is a ham radio VoIP client using vendor-operated directory and connection servers |
| 15 | SimSimi (`simsimi`) | simsimi.com | collaboration/instant-messaging | Chatbot app and web service with vendor-hosted servers |
| 16 | Gridcoin (`gridcoin`) | gridcoin.us | business-systems/software-development | Cryptocurrency network with client connecting to project servers and websites |
| 17 | Chocolatey (`chocolatey`) | chocolatey.org | business-systems/software-development | Package manager client contacting chocolatey.org community package repository servers |
| 18 | Epic (`epicbrowser`) | epicbrowser.com | general-internet/internet-utility | Epic Privacy Browser, which connects to its own vendor servers |
| 19 | Travis CI (`travis-ci`) | travis-ci.com | general-internet/internet-utility | Hosted CI/CD SaaS platform with its own servers |
| 20 | Bitchat (`bitchat`) | bitchat.free | collaboration/instant-messaging | Mobile messaging app; traffic routes via vendor-run infrastructure, domain-named |
