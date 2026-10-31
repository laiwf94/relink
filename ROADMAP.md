# relink: one-year roadmap (November 2026 to October 2027)

## Vision

By October 2027 relink is a self-hostable link management platform at feature parity with Bitly, Rebrandly, Dub and Short.io for teams and enterprises: workspaces with SAML SSO, SCIM, custom roles and audit logs, custom domains with automatic TLS, targeting rules and mobile deep links, QR codes and link pages, conversion and revenue attribution, webhooks, SDKs and a web console, running highly available across regions with encryption at rest and data residency. It keeps what makes it different from every open source shortener (Kutt, Shlink, YOURLS): one small static Rust binary plus Postgres, redirects answered from memory or from a Cloudflare Worker that keep working while the database is down, and published, reproducible benchmarks with CI-enforced targets (cached redirect p99 under 1 ms at 150,000 requests per second on 8 cores, under 60 MB resident memory with 1 million cached links, a container image under 20 MB, cold start under 50 ms).

## Benchmarks and targets

Benchmarked products: Bitly, Rebrandly, Dub, Short.io (hosted SaaS, compared on features and published limits) and Kutt, Shlink, YOURLS and Dub self-hosted (compared on features and measured head to head on the same machine). Each week below names the matrix rows it closes. Targets, measured first in week 13 and re-measured in weeks 26, 44 and 51, enforced as a CI regression gate from week 13: cached redirect p99 under 1 ms and at least 150,000 requests per second on 8 cores; resident memory under 60 MB with 1 million cached links; container image under 20 MB; cold start to first served redirect under 50 ms; edge Worker bundle under 250 KB gzipped.

## 2026-11 · Tenants, domains, rules, analytics and integrations

The five core platform themes, each delivered as one week: workspaces and access control, custom domains with TLS, targeting rules and deep links, an analytics engine, and webhooks, conversions, bulk jobs and QR codes.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 1 | 2026-11-02 to 2026-11-08 | Workspaces, roles, console sign-in, audit and quotas | Every later feature needs a tenant boundary enforced in the database and real users, not only API key owners. Closes matrix rows E1, E2 and E5 (partial). |
| 2 | 2026-11-09 to 2026-11-15 | Custom domains with verification, automatic TLS and per-domain behaviour | Branded domains are the first thing every commercial shortener sells. Closes matrix rows D1, D2 and D3. |
| 3 | 2026-11-16 to 2026-11-22 | Targeting rules, deep links, scheduled changes and protected links | Leaders route by device, country and language and open native apps. Closes matrix rows L4, L6 (extends), L7, L8 and L9. |
| 4 | 2026-11-23 to 2026-11-29 | Analytics engine: raw events, HyperLogLog, query API, bots and live stream | Today's daily aggregates answer one question; leaders slice by every dimension in real time. Closes matrix rows A2, A3 and A4, and extends A1. |
| 5 | 2026-11-30 to 2026-12-06 | Webhooks, conversions, bulk jobs, QR codes, templates and search | Teams wire links into their stack and run campaigns in bulk. Closes matrix rows P3, P4, Q1, A5 (first step), A6 and L11. |

## 2026-12 · Trust, edge parity, scale-out and the console

Abuse and phishing defences, every link feature answered at the edge, read replicas and regional origins, and the first web console.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 6 | 2026-12-07 to 2026-12-13 | Abuse and trust: reputation feeds, phishing checks, reports and takedowns | A public shortener is a phishing tool unless it defends itself; every leader scans links. Closes matrix row E10. |
| 7 | 2026-12-14 to 2026-12-20 | Every link feature at the edge, with exact limits and fast invalidation | The edge today forwards limited links and waits for KV propagation. Extends matrix row F1 to every feature. |
| 8 | 2026-12-21 to 2026-12-27 | Read replicas, membership filter, regional origins and point-in-time recovery | One Postgres primary is the scale and availability ceiling. Closes matrix row E7 (first step). |
| 9 | 2026-12-28 to 2027-01-03 | Web console: links, analytics, workspace admin and bulk tools | Every leader is used through a console; relink only has an API. Closes the console part of matrix rows A1, P4 and E1. |

## 2027-01 · SDKs, experiments, operations and the benchmark

API v2 with SDKs in three languages and a CLI, experiments with bandits and sequential tests, release and lifecycle operations, and the published head-to-head benchmark that becomes a CI gate.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 10 | 2027-01-04 to 2027-01-10 | API v2, OpenAPI generator, TypeScript, Python and Go SDKs and a CLI | Leaders ship SDKs; relink has only raw HTTP. Closes matrix rows P1 (v2), P2 and P5. |
| 11 | 2027-01-11 to 2027-01-17 | Experiments: bandits, sequential tests, holdouts and preview overrides | A/B splits exist; deciding a winner does not. Extends matrix row L5 and closes L10. |
| 12 | 2027-01-18 to 2027-01-24 | Operations: tracing, data lifecycle, signed releases, Helm and safe migrations | The one week of cross-cutting operations work: observability, release engineering and data lifecycle together. Closes matrix rows E9 and E12 (lifecycle part). |
| 13 | 2027-01-25 to 2027-01-31 | Head-to-head benchmark against Kutt, Shlink, YOURLS and Dub, enforced in CI | Lightweight and fast is relink's claim against every competitor, so it is measured early and guarded for the rest of the year. Matrix row F2. |

## 2027-02 · Enterprise identity and encryption

SAML SSO, SCIM 2.0 provisioning, custom roles with fine-grained grants, and envelope encryption with key rotation.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 14 | 2027-02-01 to 2027-02-07 | SAML 2.0 single sign-on with enforced SSO and just-in-time provisioning | Bitly, Rebrandly, Dub and Short.io all sell SAML SSO on their enterprise plans. Matrix row E3. |
| 15 | 2027-02-08 to 2027-02-14 | SCIM 2.0 user and group provisioning | Enterprises provision and remove people from their identity provider, and the leaders support it. Matrix row E4. |
| 16 | 2027-02-15 to 2027-02-21 | Custom roles and fine-grained grants per folder and domain | Large teams need to limit who edits which campaigns and domains; leaders sell this on enterprise plans. Matrix rows E2 and E11 (groundwork). |
| 17 | 2027-02-22 to 2027-02-28 | Envelope encryption at rest with online key rotation and external key providers | Encryption at rest with customer-managed keys is a procurement requirement. Matrix row E12. |

## 2027-03 · Compliance, high availability and recovery

Compliance-grade audit streaming, highly available singletons and zero-downtime deploys, regional data residency, a Kubernetes operator and workspace-level disaster recovery.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 18 | 2027-03-01 to 2027-03-07 | Compliance-grade audit streaming to SIEMs | Security teams want audit events in their own SIEM with proof that nothing was removed. Matrix row E5. |
| 19 | 2027-03-08 to 2027-03-14 | Highly available workers, graceful drains and zero-downtime deploys | Enterprise plans carry uptime SLAs, and relink's background workers assume one instance per job. Matrix row E7. |
| 20 | 2027-03-15 to 2027-03-21 | Data residency with region-pinned workspaces | Enterprise and EU customers require data to stay in a chosen region; leaders offer it on top plans. Matrix row E6. |
| 21 | 2027-03-22 to 2027-03-28 | Kubernetes operator | Self-hosting enterprises deploy on Kubernetes and expect upgrades to be managed. Matrix row E9. |
| 22 | 2027-03-29 to 2027-04-04 | Workspace backup, restore and measured disaster recovery | Enterprises need single-tenant restore and proven recovery objectives. Matrix row E7. |

## 2027-04 · Scale and the lightweight core

Sharding to billions of links, then the memory, throughput and cold-start work that makes relink the lightest and fastest link platform, re-measured against the benchmark.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 23 | 2027-04-05 to 2027-04-11 | Sharding links across Postgres clusters | Bitly-scale tenants hold billions of links, beyond one primary. Matrix row D4. |
| 24 | 2027-04-12 to 2027-04-18 | Memory footprint: compact cache entries, interning and arenas | Small memory per link is where a Rust binary beats PHP, Node and JVM competitors. Matrix row F2. |
| 25 | 2027-04-19 to 2027-04-25 | Hot path throughput: per-core listeners and allocation-free redirects | Top throughput and p99 against every competitor. Matrix row F2. |
| 26 | 2027-04-26 to 2027-05-02 | Static binary, small image, fast cold start and the second-quarter benchmark | Lightweight deployment and instant scale-out. Matrix row F2. |

## 2027-05 · Analytics and attribution at scale

A columnar analytics backend, real-time dashboards, lead and sale attribution, partner programs and link-in-bio pages.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 27 | 2027-05-03 to 2027-05-09 | Columnar analytics backend for ten billion events | Leaders answer analytics over years of clicks in milliseconds; partitioned Postgres will not. Matrix rows A1 and A7. |
| 28 | 2027-05-10 to 2027-05-16 | Real-time analytics at scale | Live dashboards are a headline feature of Bitly and Dub, and relink's live stream is per instance. Matrix row A3. |
| 29 | 2027-05-17 to 2027-05-23 | Lead and sale attribution with multi-touch models | Dub and Bitly sell attribution of sign-ups and revenue to links; relink stops at conversions. Matrix row A5. |
| 30 | 2027-05-24 to 2027-05-30 | Partner and affiliate programs | Dub sells partner programs built on attribution, and it is a growing reason teams choose it. Matrix row P6. |
| 31 | 2027-05-31 to 2027-06-06 | Link-in-bio and landing pages | Bitly and Short.io sell link pages; they turn a shortener into a marketing surface. Matrix row Q3. |

## 2027-06 · QR, domains and integrations at scale

A full QR platform, domain management at scale with DNS-01 and wildcards, event forwarding integrations and global API rate plans.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 32 | 2027-06-07 to 2027-06-13 | QR code platform: design, dynamic codes and print export | Bitly treats QR as a product of its own, with designed codes and scan analytics. Matrix row Q2. |
| 33 | 2027-06-14 to 2027-06-20 | Domains at scale: DNS-01, wildcards and domain health | Agencies run hundreds of domains; leaders monitor them and issue certificates without HTTP access. Matrix rows D2 and D4. |
| 34 | 2027-06-21 to 2027-06-27 | Event forwarding integrations | Leaders push click and conversion events into the customer's analytics and chat tools. Matrix row A8. |
| 35 | 2027-06-28 to 2027-07-04 | Global API rate plans | Leaders sell API quotas per plan enforced across all servers; relink's rate limits are per instance. Matrix row P1. |

## 2027-07 · Billing, workflows and mobile deep linking

Usage-based billing, approval workflows, iOS and Android SDKs and deferred deep linking.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 36 | 2027-07-05 to 2027-07-11 | Usage-based billing | Hosted operators need to charge by plan and usage; leaders bill by links, clicks and seats. Matrix row E1 (commercial part). |
| 37 | 2027-07-12 to 2027-07-18 | Approval workflows and collaboration | Regulated teams require review before links on brand domains go live. Matrix row E11. |
| 38 | 2027-07-19 to 2027-07-25 | iOS and Android SDKs for deep link attribution | Deep linking that opens apps and attributes installs needs native SDKs; Dub and Bitly offer deep links. Matrix row L8. |
| 39 | 2027-07-26 to 2027-08-01 | Deferred deep linking | Sending a new user to the right screen after install is the feature mobile teams pay for. Matrix row L8. |

## 2027-08 · Global console, trust and portable edge

A localised and accessible console, a cross-workspace reputation service, relink-core on any WASI HTTP edge, a threat-model pass and the third-quarter tail-latency work.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 40 | 2027-08-02 to 2027-08-08 | Localised and accessible console | International teams buy tools in their own language, and accessibility is a contract term in public-sector deals. Matrix row E1 (console). |
| 41 | 2027-08-09 to 2027-08-15 | Reputation service: RDAP, certificate transparency and shared signals | Bitly and Rebrandly block phishing with signals from their whole customer base; relink's checks are per link. Matrix row E10. |
| 42 | 2027-08-16 to 2027-08-22 | relink-core on any WASI HTTP edge | Edge redirects are tied to Cloudflare Workers today; a portable component keeps self-hosters vendor-neutral. Matrix row F1. |
| 43 | 2027-08-23 to 2027-08-29 | Threat model and security hardening | Enterprise security reviews ask for a threat model and evidence of testing at every boundary. Matrix row E12. |
| 44 | 2027-08-30 to 2027-09-05 | Tail latency under overload and the third-quarter benchmark | p99.9 under overload is where outages begin, and no competitor publishes it. Matrix row F2. |

## 2027-09 · Organizations, data export and migration

Organizations over many workspaces, warehouse exports, importers from the leading shorteners and search across a hundred million links.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 45 | 2027-09-06 to 2027-09-12 | Organizations over many workspaces | Large companies run many brands and teams and want one place for policy, identity and billing. Matrix rows E1 and E2. |
| 46 | 2027-09-13 to 2027-09-19 | Data warehouse exports in Parquet and NDJSON | Enterprise analysts want raw events in their own warehouse. Matrix row A7. |
| 47 | 2027-09-20 to 2027-09-26 | Importers from Bitly, Rebrandly, Short.io, Dub, Kutt and Shlink | Switching cost is the biggest barrier to winning customers from the leaders. Matrix row P7. |
| 48 | 2027-09-27 to 2027-10-03 | Search and saved views across a hundred million links | Large workspaces find links by any field in milliseconds on the leaders. Matrix row L11. |

## 2027-10 · Upgrades, soak and 1.0

Cross-version upgrades, a week-long soak with fault injection, the final benchmark report and the 1.0 release.

| Week | Dates | Deliverable | Why |
|---|---|---|---|
| 49 | 2027-10-04 to 2027-10-10 | Cross-version upgrades and API compatibility checks | Enterprises upgrade on their schedule and cannot afford breaking changes. Matrix row E9. |
| 50 | 2027-10-11 to 2027-10-17 | Week-long soak with fault injection | Uptime claims need evidence over days, not minutes. Matrix row E7. |
| 51 | 2027-10-18 to 2027-10-24 | Final benchmark report against the leaders | The year closes with numbers that back the lightweight claim. Matrix row F2. |
| 52 | 2027-10-25 to 2027-10-31 | relink 1.0 | A stable release with frozen APIs and the documentation enterprises expect. Closes the remaining partial rows in the matrix. |

## Next year

Gaps from the comparison still open after October 2027: SOC 2 Type II and ISO 27001 certification (row E12; controls and evidence are built, the audit is organisational), a hosted multi-tenant service with a contractual SLA (row E7), direct partner payouts across countries (row P6), native mobile console apps and a browser extension, and listings in third-party automation marketplaces (row A8).
