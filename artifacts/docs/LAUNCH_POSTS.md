# Launch Posts

Drafts for announcing the catalog. Casual, no em dashes, no marketing voice.
Edit freely, these are starting points not finished copy.

---

## LinkedIn (main post)

> Been building something for the past few weeks and it's public now.
>
> AI coding agents and local LLM runtimes are all over enterprise endpoints at
> this point. Claude Code, Cursor, Cline, Ollama, LM Studio, MCP servers. They
> got installed by developers, not by IT, and most security teams have no
> inventory of them.
>
> Here's the thing that got my attention. These tools leave a really regular set
> of traces. Dot directories with API tokens sitting in plaintext. Config files
> that quietly spawn child processes every time the app starts. Inference APIs
> listening on well known ports with no authentication at all. Session
> transcripts holding entire source trees.
>
> So if you catch an incident on a developer workstation tomorrow, where do you
> look? What does each file actually prove? What do you grab first?
>
> I couldn't find a good answer to that, so I wrote one.
>
> It's a machine readable catalog of 44 tools. Install paths, credential
> locations, MCP configs, listening ports, process trees, registry keys. Every
> artifact is rated by forensic value and by how well sourced it is, and every
> entry has a collection priority for triage.
>
> A few things I decided on early and would defend:
>
> Detections ship as Sigma, not SPL or KQL. One rule converts to whatever you
> run. CI checks every rule actually compiles so nothing ships broken.
>
> The confidence field is the one that matters. A reference that overstates
> certainty is worse than one with gaps, because people build detections on it.
> Anything single sourced is flagged as unverified, and the validator blocks a
> high confidence entry that hides a low confidence path.
>
> It exports to ForensicArtifacts format, so it drops into Plaso, GRR, and
> Timesketch instead of asking anyone to adopt yet another format.
>
> Three case studies in there too, including Langflow CVE-2025-3248. That one is
> on CISA KEV, was mass exploited to drop the Flodrix botnet, and attackers found
> targets by scanning for the default port. AI agent infrastructure is not a
> theoretical target anymore.
>
> It's part of my ai-dfir-toolkit repo. Built independently, on my own time.
> Corrections very welcome, especially if you can verify a path on a real host
> that I couldn't.
>
> [link]
>
> #DFIR #IncidentResponse #AISecurity #DetectionEngineering #ThreatHunting

---

## LinkedIn (short version, if you want something lighter)

> Quick question for the DFIR folks. A developer workstation gets popped and they
> had Claude Code, Cursor, and Ollama installed. Where do you look first?
>
> I got tired of not having a good answer, so I built a catalog. 44 AI agents and
> LLM runtimes, with install paths, credential locations, MCP configs, listening
> ports, and process trees. Everything rated by forensic value and by how well
> sourced it is.
>
> Detections are Sigma so they convert to whatever SIEM you run. It also exports
> to ForensicArtifacts format for Plaso and GRR.
>
> Free, open, corrections welcome.
>
> [link]

---

## Slack or Discord community post

> hey folks, put something out today that might be useful
>
> it's an artifact catalog for AI agents on endpoints. 44 tools covering coding
> agents, local LLM runtimes, MCP servers, browser agents. paths, creds, ports,
> process trees, the usual stuff you want at 2am
>
> the bit I think is actually useful is the MCP coverage. an MCP config is
> basically a persistence mechanism and an execution primitive in one file, it
> launches child processes at every app start with inherited env, and a lot of
> them travel with a git clone. worth knowing where they live
>
> sigma rules included so it should drop into whatever you run
>
> would really appreciate corrections if you spot a wrong path. that's the main
> way this stays useful
>
> [link]

---

## If someone asks "why not just use LOLBAS style"

Worth having the answer ready, it comes up:

> Different question. LOLBAS and LOLRMM answer "what can this tool be abused to
> do." This answers "what did it leave on the host, what does that prove, and
> what do I collect first." That's why every artifact has a forensic value rating
> and an evidence type, and every entry has a collection priority. It's built for
> the person doing the acquisition, not the person doing the threat model.

## If someone asks about false positives

> Most of these tools are completely legitimate software and presence is not an
> incident. That's why several of the Sigma rules are deliberately level: low. An
> agent spawning a shell on a developer box is the product working correctly. If
> I shipped that as high severity it would just train people to ignore the feed.
> The high severity rules are the ones that are hard to explain as normal use,
> like a plaintext token getting read by something that doesn't own it, or an
> inference endpoint quietly pointed somewhere else.
