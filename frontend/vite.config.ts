import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'fs'
import path from 'path'
import.meta.dirname

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, 
    https: {
      cert: fs.readFileSync(path.resolve(import.meta.dirname, '../certs/dev.pem')),
      key: fs.readFileSync(path.resolve(import.meta.dirname, '../certs/dev.key'))
    }
  },
})
