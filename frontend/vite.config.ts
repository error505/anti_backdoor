import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev workflow: start the backend with BACKDOOR_WATCH_TOKEN set, then open
// http://localhost:5173/#token=<same token>. changeOrigin keeps the Host header
// on 127.0.0.1 so the backend's loopback guard accepts proxied requests.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8765", changeOrigin: true },
    },
  },
});
