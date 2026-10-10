import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

export default function Launch({ preselected, onLaunched }) {
  const [tools, setTools] = useState([])
  const [toolName, setToolName] = useState(preselected || '')
  const [params, setParams] = useState({})
  const [error, setError] = useState('')
  const [launching, setLaunching] = useState(false)

  useEffect(() => {
    api.listTools().then(setTools).catch((e) => setError(`Failed to load tools: ${e.message}`))
  }, [])
  useEffect(() => { if (preselected) setToolName(preselected) }, [preselected])

  const tool = useMemo(() => tools.find((t) => t.name === toolName), [tools, toolName])

  useEffect(() => {
    // reset params when tool changes
    if (tool) {
      const init = {}
      for (const p of tool.params) init[p.name] = p.default || ''
      setParams(init)
    }
  }, [toolName])

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setLaunching(true)
    try {
      const { job_id } = await api.launch(toolName, params)
      onLaunched(job_id)
    } catch (err) {
      setError(String(err.message || err))
    } finally {
      setLaunching(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold">Launch a tool</h1>

      <form onSubmit={submit} className="space-y-4 rounded-lg border border-slate-800 bg-slate-900/50 p-6">
        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-500">Tool</label>
          <select
            value={toolName}
            onChange={(e) => setToolName(e.target.value)}
            className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm focus:border-emerald-500 focus:outline-none"
          >
            <option value="">— select a tool —</option>
            {tools.map((t) => (
              <option key={t.name} value={t.name}>
                [{t.category}] {t.display_name}
              </option>
            ))}
          </select>
        </div>

        {tool && (
          <>
            <p className="text-sm text-slate-400">{tool.description}</p>

            {tool.params.map((p) => (
              <div key={p.name}>
                <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-500">
                  {p.label || p.name}
                  {p.required && <span className="text-red-400"> *</span>}
                </label>
                {p.type === 'select' ? (
                  <select
                    value={params[p.name] || ''}
                    onChange={(e) => setParams({ ...params, [p.name]: e.target.value })}
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm focus:border-emerald-500 focus:outline-none"
                  >
                    {p.options.map((o) => <option key={o} value={o}>{o || '—'}</option>)}
                  </select>
                ) : p.type === 'bool' ? (
                  <input
                    type="checkbox"
                    checked={!!params[p.name]}
                    onChange={(e) => setParams({ ...params, [p.name]: e.target.checked })}
                    className="h-4 w-4 accent-emerald-500"
                  />
                ) : (
                  <input
                    type="text"
                    value={params[p.name] || ''}
                    onChange={(e) => setParams({ ...params, [p.name]: e.target.value })}
                    placeholder={p.type === 'flag' ? `${p.flag || '--flag'} <value>` : ''}
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm focus:border-emerald-500 focus:outline-none"
                  />
                )}
                {p.help && <p className="mt-1 text-xs text-slate-500">{p.help}</p>}
              </div>
            ))}
          </>
        )}

        {error && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</div>}

        <button
          disabled={!toolName || launching}
          className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-40"
        >
          {launching ? 'Starting container…' : 'Run'}
        </button>
      </form>
    </div>
  )
}
