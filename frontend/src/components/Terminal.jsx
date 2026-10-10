import React, { useEffect, useRef } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import { getToken } from '../api.js'

export default function TerminalPage() {
  const holder = useRef(null)
  const termRef = useRef(null)

  useEffect(() => {
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'Consolas, "Courier New", monospace',
      theme: { background: '#020617' },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(holder.current)
    fit.fit()
    termRef.current = term
    term.writeln('\x1b[36mCPTM web terminal — toolbox container (/bin/bash)\x1b[0m')
    term.writeln('')

    const proto = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${location.host}/ws/terminal?token=${encodeURIComponent(getToken())}`)
    let opened = false

    ws.binaryType = 'arraybuffer'
    ws.onopen = () => { opened = true }
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') term.write(ev.data)
      else term.write(new Uint8Array(ev.data))
    }
    ws.onclose = () => {
      term.writeln('\r\n\x1b[31m[terminal closed]\x1b[0m')
    }

    const inputDecoder = (data) => {
      if (opened && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }))
      }
    }
    term.onData(inputDecoder)

    const onResize = () => fit.fit()
    window.addEventListener('resize', onResize)

    return () => {
      window.removeEventListener('resize', onResize)
      ws.close()
      term.dispose()
    }
  }, [])

  return (
    <div className="flex h-full flex-col space-y-3">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Terminal</h1>
        <span className="text-xs text-slate-500">interactive shell in the toolbox container — all tools on PATH, creds at /creds</span>
      </div>
      <div
        ref={holder}
        className="min-h-0 flex-1 overflow-hidden rounded-lg border border-slate-800 bg-black p-2"
      />
    </div>
  )
}
