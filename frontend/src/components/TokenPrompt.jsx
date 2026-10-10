import React, { useState } from 'react'
import { api, setToken } from '../api.js'

export default function TokenPrompt({ onOk }) {
  const [val, setVal] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    if (!val.trim()) {
      setErr('Enter the CPTM_TOKEN from your .env file')
      return
    }
    setErr('')
    setBusy(true)
    setToken(val.trim())
    try {
      // Verify before entering the app, so a wrong token shows an error here
      // rather than an empty dashboard.
      await api.authCheck()
      onOk()
    } catch (e2) {
      setErr('Invalid token — check CPTM_TOKEN in your .env file')
      setBusy(false)
    }
  }

  return (
    <div className="flex h-full items-center justify-center">
      <form
        onSubmit={submit}
        className="w-96 rounded-lg border border-slate-800 bg-slate-900 p-6 space-y-4"
      >
        <div>
          <div className="text-lg font-bold text-emerald-400">CPTM</div>
          <div className="text-sm text-slate-400">
            Enter your access token (<code className="text-slate-300">CPTM_TOKEN</code> from{' '}
            <code className="text-slate-300">cloud-pentest-manager/.env</code>)
          </div>
        </div>
        <input
          type="password"
          value={val}
          onChange={(e) => setVal(e.target.value)}
          placeholder="token"
          className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm focus:border-emerald-500 focus:outline-none"
          autoFocus
        />
        {err && <div className="text-xs text-red-400">{err}</div>}
        <button
          disabled={busy}
          className="w-full rounded bg-emerald-500 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-50"
        >
          {busy ? 'Checking…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
