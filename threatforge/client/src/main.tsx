import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// Apply saved theme BEFORE first paint to prevent flash
;(function applyInitialTheme() {
  const saved = localStorage.getItem('threatforge_theme_v2') ||
    (localStorage.getItem('threatforge_theme') === 'light' ? 'arctic' : 'ocean')
  const lightThemes = ['arctic', 'sand']
  document.documentElement.setAttribute('data-theme', saved)
  if (lightThemes.includes(saved)) {
    document.documentElement.classList.remove('dark')
  } else {
    document.documentElement.classList.add('dark')
  }
})()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
