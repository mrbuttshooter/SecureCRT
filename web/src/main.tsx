import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
// xterm's stylesheet is bundled rather than linked from a CDN: the content
// security policy allows styles from this origin only.
// Fonts are bundled for the same reason: font-src permits this origin only.
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '@fontsource/ibm-plex-mono/600.css'
import '@xterm/xterm/css/xterm.css'
import './styles.css'

const root = document.getElementById('root')
if (!root) throw new Error('missing #root element')

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
