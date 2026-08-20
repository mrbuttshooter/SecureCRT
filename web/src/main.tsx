import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
// xterm's stylesheet is bundled rather than linked from a CDN: the content
// security policy allows styles from this origin only.
import '@xterm/xterm/css/xterm.css'
import './styles.css'

const root = document.getElementById('root')
if (!root) throw new Error('missing #root element')

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
