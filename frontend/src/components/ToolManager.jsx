import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const EMPTY = {
  name: '',
  display_name: '',
  description: '',
  category: 'general',
  docker_image: '',
  command_template: '',
  output_type: 'generic',
  params: [],
}

export default function ToolManager({ onLaunch }) {
  const [tools, setTools] = useState([])
  const [editing, setEditing] = useState(null) // null | 'new' | tool-name
  const [form, setForm] = useState(EMPTY)
  const [msg, setMsg] = useState(null)

  const load = () =>
    api
      .listTools()
      .then(setTools)
      .catch((e) => setMsg({ type: 'error', text: `Failed to load tools: ${e.message}` }))
  useEffect(() => { load() }, [])

  const startNew = () => { setForm(EMPTY); setEditing('new'); setMsg(null) }
  const startEdit = (t) => {
    setForm({
      name: t.name,
      display_name: t.display_name,
      description: t.description,
      category: t.category,
      docker_image: t.docker_image,
      command_template: t.command_template,
      output_type: t.output_type,
      params: t.params,
    })
    setEditing(t.name)
    setMsg(null)
  }

  const save = async (e) => {
    e.preventDefault()
    setMsg(null)
    try {
      const spec = {
        ...form,
        params: form.params.filter((p) => p.name),
      }
      if (editing === 'new') await api.createTool(spec)
      else await api.updateTool(editing, spec)
      setEditing(null)
      load()
    } catch (err) {
      setMsg({ type: 'error', text: String(err.message || err) })
    }
  }

  const remove = async (name) => {
    if (!confirm(`Delete tool "${name}"?`)) return
    try { await api.deleteTool(name); load() } catch (err) { setMsg({ type: 'error', text: err.message }) }
  }

  const addParam = () => setForm({ ...form, params: [...form.params, { name: '', label: '', type: 'string', default: '', required: false, help: '' }] })
  const setParam = (i, key, val) => {
    const params = form.params.map((p, idx) => (idx === i ? { ...p, [key]: val } : p))
    setForm({ ...form, params })
  }
  const delParam = (i) => setForm({ ...form, params: form.params.filter((_, idx) => idx !== i) })

  if (editing) {
    const isNew = editing === 'new'
    return (
      <form onSubmit={save} className="mx-auto max-w-3xl space-y-5">
        <h1 className="text-2xl font-bold">{isNew ? 'Add tool' : `Edit: ${editing}`}</h1>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Name (unique id)">
            <input required disabled={!isNew} value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              className={inputCls + ' disabled:opacity-50'} placeholder="my-scanner" />
          </Field>
          <Field label="Display name">
            <input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} className={inputCls} />
          </Field>
          <Field label="Category">
            <select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} className={inputCls}>
              {['aws', 'azure', 'gcp', 'kubernetes', 'general'].map((c) => <option key={c}>{c}</option>)}
            </select>
          </Field>
          <Field label="Output type (findings parser)">
            <select value={form.output_type} onChange={(e) => setForm({ ...form, output_type: e.target.value })} className={inputCls}>
              {[
                'generic', 'prowler', 'scoutsuite', 'trivy', 'kube-hunter', 'kube-bench',
                'nmap', 'cloud-enum', 'cloudbrute', 'cloudfox', 'enumerate-iam',
                'gcp-scanner', 'microburst',
              ].map((c) => <option key={c}>{c}</option>)}
            </select>
          </Field>
        </div>

        <Field label="Description">
          <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className={inputCls} />
        </Field>

        <Field label="Docker image (empty = toolbox image)">
          <input value={form.docker_image} onChange={(e) => setForm({ ...form, docker_image: e.target.value })} className={inputCls + ' font-mono'} placeholder="cptm-toolbox:latest" />
        </Field>

        <Field label="Command template — use {param_name} placeholders; {job_id} is injected automatically">
          <input required value={form.command_template}
            onChange={(e) => setForm({ ...form, command_template: e.target.value })}
            className={inputCls + ' font-mono'} placeholder="prowler aws {profile} {extra_args}" />
        </Field>
        <p className="text-xs text-slate-500">
          Parameter types: <code>string</code> (raw value), <code>bool</code>, <code>select</code>, and{' '}
          <code>flag</code> — a <code>flag</code> param renders as <code>--name value</code> and is
          omitted from the command entirely when left empty (use it for optional CLI switches).
        </p>

        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Parameters</span>
            <button type="button" onClick={addParam} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-emerald-500 hover:text-emerald-300">+ param</button>
          </div>
          <div className="space-y-2">
            {form.params.map((p, i) => (
              <div key={i} className="grid grid-cols-12 gap-2 rounded border border-slate-800 bg-slate-900/50 p-2">
                <input placeholder="name" value={p.name} onChange={(e) => setParam(i, 'name', e.target.value)} className={inputCls + ' col-span-2 font-mono'} />
                <input placeholder="label" value={p.label} onChange={(e) => setParam(i, 'label', e.target.value)} className={inputCls + ' col-span-2'} />
                <select value={p.type} onChange={(e) => setParam(i, 'type', e.target.value)} className={inputCls + ' col-span-2'}>
                  {['string', 'bool', 'select', 'flag'].map((t) => <option key={t}>{t}</option>)}
                </select>
                <input placeholder={p.type === 'flag' ? '--flag' : 'default'} value={p.type === 'flag' ? (p.flag || '') : p.default}
                  onChange={(e) => setParam(i, p.type === 'flag' ? 'flag' : 'default', e.target.value)} className={inputCls + ' col-span-2 font-mono'} />
                <label className="col-span-2 flex items-center gap-1 text-xs text-slate-400">
                  <input type="checkbox" checked={p.required} onChange={(e) => setParam(i, 'required', e.target.checked)} className="accent-emerald-500" />
                  required
                </label>
                <button type="button" onClick={() => delParam(i)} className="col-span-1 rounded text-red-400 hover:bg-red-500/10">✕</button>
                <input placeholder="help text" value={p.help} onChange={(e) => setParam(i, 'help', e.target.value)} className={inputCls + ' col-span-11'} />
              </div>
            ))}
          </div>
        </div>

        {msg && <div className={`rounded border px-3 py-2 text-sm ${msg.type === 'error' ? 'border-red-500/40 bg-red-500/10 text-red-300' : 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'}`}>{msg.text}</div>}

        <div className="flex gap-3">
          <button className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400">Save tool</button>
          <button type="button" onClick={() => setEditing(null)} className="rounded border border-slate-700 px-4 py-2 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
        </div>
      </form>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Tool Manager</h1>
        <button onClick={startNew} className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400">+ Add tool</button>
      </div>

      {msg && <div className="rounded border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-300">{msg.text}</div>}

      <div className="grid gap-3 md:grid-cols-2">
        {tools.map((t) => (
          <div key={t.name} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
            <div className="mb-1 flex items-center justify-between">
              <div>
                <span className="font-semibold">{t.display_name}</span>
                <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase text-emerald-300">{t.category}</span>
                {t.built_in ? <span className="ml-1 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">built-in</span>
                  : <span className="ml-1 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-sky-300">custom</span>}
              </div>
              <div className="flex gap-2 text-xs">
                <button onClick={() => onLaunch(t.name)} className="text-emerald-300 hover:underline">run</button>
                <button onClick={() => startEdit(t)} className="text-slate-400 hover:underline">edit</button>
                <button onClick={() => remove(t.name)} className="text-red-400 hover:underline">delete</button>
              </div>
            </div>
            <p className="mb-2 text-xs text-slate-500">{t.description}</p>
            <code className="block truncate rounded bg-slate-950 px-2 py-1 text-[11px] text-slate-400">{t.command_template}</code>
          </div>
        ))}
      </div>
    </div>
  )
}

const inputCls =
  'rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-sm focus:border-emerald-500 focus:outline-none'

function Field({ label, children }) {
  return (
    <div>
      <label className="mb-1 block text-xs font-semibold uppercase tracking-wider text-slate-500">{label}</label>
      {children}
    </div>
  )
}
