import React, { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard.jsx'
import Launch from './components/Launch.jsx'
import JobView from './components/JobView.jsx'
import Terminal from './components/Terminal.jsx'
import ToolManager from './components/ToolManager.jsx'
import TokenPrompt from './components/TokenPrompt.jsx'
import { api, clearToken, setUnauthorizedHandler } from './api.js'

const PAGES = ['dashboard', 'launch', 'jobs', 'terminal', 'tools']

export default function App() {
  const [page, setPage] = useState('dashboard')
  // null = still checking, true = authenticated, false = show login
  const [authed, setAuthed] = useState(null)
  const [activeJob, setActiveJob] = useState(null)
  const [selectedTool, setSelectedTool] = useState(null)

  useEffect(() => {
    // Any 401 anywhere in the app drops us back to the login screen instead of
    // leaving the user staring at an empty page.
    setUnauthorizedHandler(() => setAuthed(false))
  }, [])

  const checkAuth = () => {
    setAuthed(null)
    api
      .authCheck()
      .then(() => setAuthed(true))
      .catch(() => setAuthed(false))
  }

  useEffect(() => {
    checkAuth()
  }, [])

  if (authed === null) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-slate-500">
        Connecting…
      </div>
    )
  }

  if (authed === false) {
    return (
      <TokenPrompt
        onOk={() => {
          setAuthed(true)
        }}
        onError={(msg) => {
          clearToken()
          setAuthed(false)
        }}
      />
    )
  }

  const openJob = (job) => {
    setActiveJob(job)
    setPage('jobs')
  }
  const openLaunch = (toolName) => {
    setSelectedTool(toolName)
    setPage('launch')
  }

  return (
    <div className="flex h-full">
      <nav className="w-52 shrink-0 border-r border-slate-800 bg-slate-900 p-4 flex flex-col gap-1">
        <div className="mb-4 px-2">
          <div className="text-lg font-bold tracking-tight text-emerald-400">CPTM</div>
          <div className="text-[11px] text-slate-500">Cloud Pentest Tool Manager</div>
        </div>
        {PAGES.map((p) => (
          <button
            key={p}
            onClick={() => setPage(p)}
            className={`rounded px-3 py-2 text-left text-sm capitalize transition ${
              page === p
                ? 'bg-emerald-500/15 text-emerald-300'
                : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
            }`}
          >
            {p === 'jobs' ? 'jobs & output' : p}
          </button>
        ))}
        <button
          onClick={() => {
            clearToken()
            setAuthed(false)
          }}
          className="mt-2 rounded px-3 py-2 text-left text-xs text-slate-500 hover:bg-slate-800 hover:text-slate-300"
        >
          sign out
        </button>
        <div className="mt-auto text-[10px] text-slate-600">
          authorized engagements only
        </div>
      </nav>

      <main className="flex-1 overflow-auto p-6">
        {page === 'dashboard' && (
          <Dashboard onOpenJob={openJob} onLaunch={openLaunch} onAuthError={checkAuth} />
        )}
        {page === 'launch' && (
          <Launch preselected={selectedTool} onLaunched={openJob} />
        )}
        {page === 'jobs' && <JobView jobId={activeJob} onBack={() => setPage('dashboard')} />}
        {page === 'terminal' && <Terminal />}
        {page === 'tools' && <ToolManager onLaunch={openLaunch} />}
      </main>
    </div>
  )
}
