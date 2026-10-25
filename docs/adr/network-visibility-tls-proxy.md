ADR: Live Network Visibility via Local TLS-Intercepting Proxy
================================================================

Status
------
Proposed

Context
-------
AgentWatch's security detectors (NetworkAnomalyDetector,
DataExfiltrationDetector, C2CommunicationDetector) depend on
Action.network_host / Action.network_port. Today those fields are only
populated by the Moltbot log parser. The Claude Code parser
(parser/logs.py::parse_claude_code_entry) never sets them, because Claude
Code's session log only records the raw bash command string for tool calls,
not any structured network metadata. As a result, host/port-based detection
silently never fires for Claude Code sessions -- the primary supported agent
-- and AgentWatch's only real signal is regex matching against command text
(curl, wget, -d), which is easy to miss or evade.

We want AgentWatch to answer, in real time: which hosts/URLs is this agent
process actually talking to.

Decision
--------
Capture traffic by running the monitored agent as a child process through a
local TLS-intercepting proxy (mitmproxy/mitmdump), rather than by polling
OS-level sockets or trying to enrich existing log parsers.

The proxy decrypts and logs each outbound request (host, port, full URL,
method, status, size, timestamp) to a side channel that AgentWatch tails and
converts into Action objects, merged into the existing ActionBuffer alongside
tool-call actions.

Threat Model / Trust Implications
----------------------------------
This design requires installing a custom root CA trusted by the wrapped
child process, so mitmdump can decrypt and re-encrypt the agent's own TLS
traffic -- including calls to Anthropic's API. This is the same interception
technique used by corporate proxies and, less charitably, by malware, so it
deserves explicit justification given AgentWatch's own pitch is "security
guard for agents":

- The CA is generated fresh per invocation (session-scoped), not a
  long-lived cert installed into the system trust store.
- Trust is scoped only to the environment of the single wrapped child
  process (via REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS / SSL_CERT_FILE),
  never the OS-wide trust store.
- The proxy and cert are torn down when the wrapped process exits --
  including non-graceful exits (see Consequences).
- The feature is strictly opt-in via a new `agentwatch run` subcommand;
  existing check/watch/security-scan flows never install a CA or intercept
  traffic.
- All interception and logging happens entirely on the user's own machine;
  nothing is transmitted externally by AgentWatch itself.

This does not eliminate the trust concern -- a user is still choosing to let
a local process decrypt their agent's traffic -- but it bounds the blast
radius to "this one wrapped session, on this one machine, for as long as it
runs."

Alternatives Considered
------------------------

Socket polling (psutil/lsof on the agent's PID).
Periodically inspect the agent process's open connections. No elevated
privileges needed, reuses AgentWatch's existing lsof-based PID discovery.
Rejected as the primary mechanism because it only yields IP:port, not
hostname or URL -- TLS-encrypted connections resolve to bare IPs, which is
much weaker signal for a security tool (an IP alone rarely tells you if a
destination is legitimate or suspicious). Fast, in-and-out connections can
also be missed between poll intervals.

Kernel-level capture (eBPF/pcap).
Would see all traffic, including subprocess traffic that doesn't inherit
proxy env vars. Rejected for v1: requires elevated privileges or kernel
modules, meaningfully higher setup cost for users, and cross-platform
support (macOS/Linux/Windows) is inconsistent. Revisit if the proxy approach
proves too lossy in practice (see Consequences).

Enriching each agent's own log format.
Ask/wait for Claude Code (or other agents) to log structured network
metadata themselves. Rejected because it's outside AgentWatch's control and
depends on upstream agent maintainers, not something we can ship.

Consequences
------------
Gains: Real hostnames/URLs instead of guesses from log text; existing
detectors start working correctly for Claude Code without detector-side code
changes; works locally without root or kernel access; scoped to a single
process launch (opt-in via a new `agentwatch run` wrapper), not a
system-wide change.

Costs / limitations, accepted for v1:

- Only sees traffic from the wrapped process and any children that inherit
  the proxy environment variables. A subprocess that clears its environment
  or ignores HTTPS_PROXY (e.g. a Bash tool call shelling out to its own curl
  with a scrubbed env) will not be captured. This is a known gap, not solved
  here -- flagged for future work (kernel-level capture would close it), and
  measured directly in the implementation plan's Build Order step 1 as a
  go/no-go check before further investment.
- Different language runtimes trust CA certificates differently (Python,
  Node, Go each need their own env var), so proxy setup may need per-runtime
  handling rather than one universal switch.
- Small latency overhead per request from the decrypt/re-encrypt hop.
  Expected negligible for typical agent API call volume.
- Logging full request/response bodies risks capturing secrets (API keys,
  file contents) in AgentWatch's own local logs.
- Logging full URLs risks capturing secrets even in metadata-only mode --
  query strings and path segments routinely carry API keys, tokens, or
  presigned-URL signatures. Mitigation: query strings and known
  secret-shaped path segments are redacted before writing to the capture
  log, in both metadata and full-capture modes (see implementation plan,
  addon script component).
- Windows: mitmproxy CA installation and per-runtime trust env vars are
  less consistent on Windows and may require admin rights. Not solved in
  v1 -- `agentwatch run` should detect and refuse cleanly on Windows rather
  than partially working, given this project has otherwise made a point of
  native Windows support (psutil-based discovery).
- Proxy lifecycle: if the wrapped agent is killed ungracefully (SIGKILL,
  crash, ctrl-C), the mitmdump process and session CA cert must still be
  cleaned up rather than orphaned. Handled via signal handler / atexit plus
  a startup liveness check that reaps any leftover instance from a prior
  crashed run before binding a new port.

Decisions Locked In (resolving the plan's open questions)
-----------------------------------------------------------
- Multi-agent support: each monitored agent gets its own mitmdump instance
  and port. Simpler isolation, avoids cross-contaminating traffic between
  agents in watch-all mode, at the cost of one proxy process per agent
  instead of one shared instance.
- Body logging default: ships metadata-only (host, port, url, method,
  status, size) by default. Full request/response body capture is opt-in
  via an explicit --capture-bodies flag, given the secret-leakage risk noted
  above. URL scrubbing applies regardless of this flag.
- Windows: not supported in v1; explicitly detected and refused with a
  clear error rather than partially working.

Related
-------
See agentwatch-network-visibility-implementation-plan.txt for the concrete
build plan, component breakdown, and validation strategy.
