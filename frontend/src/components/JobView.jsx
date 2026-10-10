import React, { useEffect, useRef, useState } from 'react'
import { api, downloadArtifact, getToken } from '../api.js'
import FindingsTable from './FindingsTable.jsx'

export default function JobView({ jobId, onBack }) {
  const [job, setJob] = useState(null)
  const [output, setOutput] = useState('')
  const [tab, setTab] = useState('output') // output | findings | artifacts
  const [findings, setFindings] = useState(null)
  const [error, setError] = useState('')
  const wsRef = useRef(null)
  const outRef = useRef(null)
  // Tracks how many characters of output the UI has already rendered, so REST
  // polling and WebSocket delivery can overlap without duplicating chunks.
  const seenRef = useRef(0)

  const appendOutput = (full) => {
    if (full.length < seenRef.current) {
      // Output was rewritten (job rerun/replay) — take it wholesale.
      seenRef.current = full.length
      setOutput(full)
      return
    }
    const fresh = full.slice(seenRef.current)
    if (fresh) {
      seenRef.current = full.length
      setOutput((prev) => {
        const next = prev + fresh
        return next.length > 2_000_000 ? next.slice(-1_000_000) : next
      })
    }
  }

  useEffect(() => {
    if (!jobId) return
    let cancelled = false
    seenRef.current = 0
    setOutput('')
    setFindings(null)
    setError('')

    api.getJob(jobId).then(setJob).catch((e) => {
      if (!cancelled) setError(e.message)
    })
    api.getOutput(jobId).then((r) => {
      if (cancelled) return
      seenRef.current = (r.output || '').length
      setOutput(r.output || '')
    }).catch((e) => {
      if (!cancelled) setError(e.message)
    })

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(
      `${proto}://${location.host}/ws/jobs/${jobId}?token=${encodeURIComponent(getToken())}`,
    )
    wsRef.current = ws
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data)
      if (msg.type === 'stream') {
        appendOutput(msg.data)
      } else if (msg.type === 'done') {
        setJob((j) => (j ? { ...j, status: msg.status, exit_code: msg.exit_code } : j))
        if (msg.findings) setFindings(msg.findings)
      }
    }

    // Polling fallback: heals missed WebSocket chunks and keeps job status fresh.
    const poll = setInterval(() => {
      api.getJob(jobId).then((j) => {
        if (!cancelled) setJob(j)
      }).catch(() => {})
      api.getOutput(jobId).then((r) => {
        if (!cancelled) appendOutput(r.output || '')
      }).catch(() => {})
    }, 3000)

    return () => {
      cancelled = true
      clearInterval(poll)
      ws.close()
    }
  }, [jobId])

  useEffect(() => {
    if (tab === 'output' && outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight
  }, [output, tab])

  useEffect(() => {
    if (tab === 'findings' && !findings) {
      api.getFindings(jobId).then(setFindings).catch(() => setFindings({ parser: 'none' }))
    }
  }, [tab])

  if (!jobId) return <div className="text-slate-500">No job selected. Go back to the dashboard.</div>
  if (error) return <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">Failed to load job: {error}</div>
  if (!job) return <div className="text-slate-500">Loading…</div>

  const running = job.status === 'running' || job.status === 'queued'
  const hasArtifacts = (job.artifacts || []).length > 0

  return (
    <div className="flex h-full flex-col space-y-4">
      <div className="flex items-center gap-3">
        <button onClick={onBack} className="rounded border border-slate-700 px-3 py-1 text-xs text-slate-400 hover:text-slate-200">← back</button>
        <h1 className="text-lg font-bold">
          #{job.id} {job.display_name || job.tool_name}
        </h1>
        <span className={`text-sm font-medium ${
          job.status === 'running' ? 'text-sky-400' :
          job.status === 'finished' ? 'text-emerald-400' :
          job.status === 'failed' ? 'text-red-400' : 'text-amber-400'
        }`}>{job.status}</span>
        {running && (
          <button
            onClick={() => api.cancel(jobId).catch(() => {})}
            className="rounded border border-red-500/50 px-3 py-1 text-xs text-red-300 hover:bg-red-500/10"
          >
            cancel
          </button>
        )}
      </div>

      <div className="rounded border border-slate-800 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-400">
        $ {job.command}
      </div>

      <div className="flex gap-1 border-b border-slate-800">
        {[
          ['output', 'Output'],
          ['findings', 'Findings'],
          ['artifacts', `Artifacts${hasArtifacts ? ` (${job.artifacts.length})` : ''}`],
        ].map(([t, label]) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm capitalize ${tab === t ? 'border-b-2 border-emerald-500 text-emerald-300' : 'text-slate-400 hover:text-slate-200'}`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1">
        {tab === 'output' && (
          <pre
            ref={outRef}
            className="h-full overflow-auto rounded-lg border border-slate-800 bg-black p-4 font-mono text-xs leading-relaxed text-slate-300"
          >{output || '(waiting for output…)'}</pre>
        )}
        {tab === 'findings' && <FindingsTable findings={findings} rawOutput={output} />}
        {tab === 'artifacts' && (
          <div className="rounded-lg border border-slate-800">
            {!hasArtifacts && (
              <div className="p-6 text-center text-sm text-slate-500">
                No artifacts. Tools writing to /artifacts/jobs/{job.id}/ appear here.
              </div>
            )}
            {hasArtifacts && (job.artifacts || []).map((a) => (
              <button
                key={a.id}
                onClick={() =>
                  downloadArtifact(job.id, a.path).catch((e) =>
                    alert(`Download failed: ${e.message}`),
                  )
                }
                className="flex w-full items-center justify-between border-b border-slate-800 px-4 py-2 text-left text-sm last:border-0 hover:bg-slate-900"
              >
                <span className="font-mono text-xs text-slate-300">{a.path}</span>
                <span className="text-xs text-slate-500">
                  {(a.size / 1024).toFixed(1)} KB ↓
                </span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
