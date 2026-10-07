/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dashboard talks to the backend through /api. In development Vite proxies /api to
// the FastAPI server; in production nginx does the same (see nginx.conf).
const backend = process.env.UPI_SHIELD_API_URL ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: backend, changeOrigin: true, rewrite: (path) => path.replace(/^\/api/, "") },
      // Swagger UI (opened from Settings) loads the schema from the site root.
      "/openapi.json": { target: backend, changeOrigin: true },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
