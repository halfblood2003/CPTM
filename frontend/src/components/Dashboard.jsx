import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const statusColor = {
  running: 'text-sky-400',
  finished: 'text-emerald-400',
  failed: 'text-red-400',
  cancelled: 'text-amber-400',
  queued: 'text-slate-400',
}

export default function Dashboard({ onOpenJob, onLaunch, onAuthError }) {
  const [jobs, setJobs] = useState([])
  const [tools, setTools] = useState([])
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const [j, t] = await Promise.all([api.listJobs(), api.listTools()])
        if (cancelled) return
        setJobs(j)
        setTools(t)
        setError('')
      } catch (e) {
        if (cancelled) return
        if (e.message === 'unauthorized') {
          if (onAuthError) onAuthError()
          return
        }
        // Surface the failure: an empty dashboard with no message is worse than
        // an error, because it looks like the tool simply has no tools.
        setError(e.message || 'failed to load')
      } finally {
        if (!cancelled) setLoaded(true)
      }
    }
    load()
    const t = setInterval(load, 4000)
    return () => {
      cancelled = true
      clearInterval(t)
    }
  }, [])

  const running = jobs.filter((j) => j.status === 'running' || j.status === 'queued')
  const byCat = {}
  for (const t of tools) (byCat[t.category] = byCat[t.category] || []).push(t)

  return (
    <div className="space-y-8">
      <div className="flex items-end justify-between">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        <button
          onClick={() => onLaunch(null)}
          className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400"
        >
          + Launch tool
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          Failed to load data: {error}
        </div>
      )}

      {loaded && !error && tools.length === 0 && (
        <div className="rounded border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          Backend returned 0 tools. Check the backend logs
          (<code>docker compose logs backend</code>) and that <code>./tools</code> is mounted.
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Running jobs" value={running.length} accent="text-sky-400" />
        <StatCard label="Total jobs" value={jobs.length} accent="text-slate-200" />
        <StatCard label="Tools registered" value={tools.length} accent="text-emerald-400" />
      </div>

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-500">
          Recent jobs
        </h2>
        <div className="overflow-hidden rounded-lg border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs uppercase text-slate-500">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Tool</th>
                <th className="px-3 py-2">Command</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Started</th>
              </tr>
            </thead>
            <tbody>
              {jobs.slice(0, 10).map((j) => (
                <tr
                  key={j.id}
                  onClick={() => onOpenJob(j.id)}
                  className="cursor-pointer border-t border-slate-800 hover:bg-slate-900"
                >
                  <td className="px-3 py-2 font-mono text-xs text-slate-400">#{j.id}</td>
                  <td className="px-3 py-2">{j.display_name || j.tool_name}</td>
                  <td className="max-w-md truncate px-3 py-2 font-mono text-xs text-slate-500">
                    {j.command}
                  </td>
                  <td className={`px-3 py-2 font-medium ${statusColor[j.status] || ''}`}>
                    {j.status}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{j.started_at}</td>
                </tr>
              ))}
              {jobs.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    No jobs yet — launch a tool
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="mb-2 text-sm font-semibold uppercase tracking-wider text-slate-500">
          Tool arsenal
        </h2>
        {tools.length === 0 ? (
          <div className="rounded-lg border border-slate-800 p-6 text-center text-sm text-slate-500">
            No tools available.
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {Object.entries(byCat).map(([cat, list]) => (
              <div key={cat} className="rounded-lg border border-slate-800 bg-slate-900/50 p-3">
                <div className="mb-2 text-xs font-bold uppercase tracking-wider text-emerald-400">
                  {cat}
                </div>
                <div className="space-y-1">
                  {list.map((t) => (
                    <button
                      key={t.name}
                      onClick={() => onLaunch(t.name)}
                      title={t.description}
                      className="block w-full truncate rounded px-2 py-1 text-left text-sm text-slate-300 hover:bg-slate-800 hover:text-emerald-300"
                    >
                      {t.display_name}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
      <div className="text-xs uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 text-3xl font-bold ${accent}`}>{value}</div>
    </div>
  )
}
