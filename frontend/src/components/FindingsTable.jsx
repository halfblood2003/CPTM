import React from 'react'

const sevColor = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/40',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
  unknown: 'bg-slate-500/10 text-slate-400 border-slate-600/40',
  fail: 'bg-red-500/15 text-red-300 border-red-500/40',
  pass: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
}

// Patterns that pull "results" out of tools that don't emit structured JSON —
// so the Findings tab is useful even when the parser is `raw`.
const RAW_EXTRACTORS = [
  {
    // nmap port lines: "80/tcp   open   http"
    re: /^(\d+\/(?:tcp|udp))\s+(open|closed|filtered)\s+(\S+)(.*)$/gm,
    build: (m) => ({
      severity: m[2] === 'open' ? 'open' : 'closed',
      id: `${m[1]}`,
      title: `${m[3]} ${m[4] || ''}`.trim(),
      service: 'portscan',
      resource: m[1],
    }),
  },
  {
    // cloud_enum / cloudbrute findings: "Open/Afound/Protected <url>"
    re: /^\s*(?:Open|Protected|A(?:vailable)?|FOUND)\s*[:\-]?\s*(https?:\/\/\S+|\S+\.(?:s3\.amazonaws\.com|blob\.core\.windows\.net|firebaseio\.com|storage\.googleapis\.com))(.*)$/gim,
    build: (m) => ({
      severity: m[0].trim().toLowerCase().startsWith('open') ? 'high' : 'medium',
      id: 'cloud-asset',
      title: m[0].trim().slice(0, 160),
      service: 'cloud-recon',
      resource: m[1],
    }),
  },
  {
    // generic "ERROR/CRITICAL" lines — make failed jobs explain themselves
    re: /^\s*(?:CRITICAL|ERROR)\b.*$/gm,
    build: (m) => ({
      severity: 'high',
      id: 'error',
      title: m[0].trim().slice(0, 180),
      service: 'stderr',
      resource: '',
    }),
  },
]

function extractFromRaw(text) {
  const findings = []
  for (const { re, build } of RAW_EXTRACTORS) {
    let m
    const rx = new RegExp(re.source, re.flags)
    while ((m = rx.exec(text)) !== null) {
      try {
        findings.push(build(m))
      } catch {
        /* ignore malformed lines */
      }
      if (findings.length > 500) break
    }
  }
  return findings
}

export default function FindingsTable({ findings, rawOutput }) {
  const structured = findings?.findings || []
  const summary = findings?.summary || {}
  const hasStructured = structured.length > 0

  // Backend parsers cover every tool; this client-side extraction is only a
  // fallback for jobs whose tool had no parser when it ran.
  const rawFindings = React.useMemo(
    () => (!hasStructured && rawOutput ? extractFromRaw(rawOutput) : []),
    [hasStructured, rawOutput],
  )

  if (!findings && !rawOutput) {
    return <div className="p-6 text-sm text-slate-500">Parsing findings…</div>
  }

  if (!hasStructured && rawFindings.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 p-6 text-center text-sm text-slate-500">
        No structured findings for this tool (parser: {findings?.parser || 'raw'}).
        The full results are in the <span className="text-slate-300">Output</span> tab.
      </div>
    )
  }

  const rows = hasStructured ? structured : rawFindings
  const sevCounts = {}
  for (const f of rows) {
    const k = (f.severity || 'unknown').toLowerCase()
    sevCounts[k] = (sevCounts[k] || 0) + 1
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3">
        <div className="rounded border border-slate-700 bg-slate-900 px-4 py-2 text-sm">
          <span className="text-slate-500">total </span>
          <span className="font-bold">{rows.length}</span>
        </div>
        {Object.entries(hasStructured ? (summary.by_severity || summary.by_status || {}) : sevCounts).map(
          ([k, v]) => (
            <div
              key={k}
              className={`rounded border px-4 py-2 text-sm ${sevColor[k.toLowerCase()] || sevColor.unknown}`}
            >
              <span className="opacity-70">{k} </span>
              <span className="font-bold">{v}</span>
            </div>
          ),
        )}
      </div>

      {!hasStructured && (
        <p className="text-xs text-slate-500">
          Extracted from raw console output ({findings?.parser || 'raw'} parser).
        </p>
      )}
      {hasStructured && (
        <p className="text-xs text-slate-500">
          Parser <span className="text-slate-300">{findings?.parser}</span>
          {findings?.source ? <> · source <span className="font-mono text-slate-400">{findings.source}</span></> : null}
          {findings?.sources?.length ? <> · merged from {findings.sources.length} artifact(s)</> : null}
        </p>
      )}

      <div className="overflow-auto rounded-lg border border-slate-800">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-slate-900 text-left text-xs uppercase text-slate-500">
            <tr>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Title</th>
              <th className="px-3 py-2">Service</th>
              <th className="px-3 py-2">Resource</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f, i) => (
              <tr key={i} className="border-t border-slate-800/60 hover:bg-slate-900/60">
                <td className="px-3 py-1.5">
                  <span
                    className={`rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase ${
                      sevColor[(f.severity || '').toLowerCase()] || sevColor.unknown
                    }`}
                  >
                    {f.severity || '—'}
                  </span>
                </td>
                <td className="px-3 py-1.5 font-mono text-xs text-slate-400">{f.id || '—'}</td>
                <td className="max-w-md truncate px-3 py-1.5 text-slate-200" title={f.title}>
                  {f.title}
                </td>
                <td className="px-3 py-1.5 text-xs text-slate-400">{f.service || '—'}</td>
                <td className="max-w-xs truncate px-3 py-1.5 font-mono text-xs text-slate-500" title={f.resource}>
                  {f.resource || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
