import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: { "/api": { target: process.env.SUDO_REQUEST_API ?? "http://127.0.0.1:4877", changeOrigin: false } },
  },
  build: { outDir: "dist", emptyOutDir: true },
})
