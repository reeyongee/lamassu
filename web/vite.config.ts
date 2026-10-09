import { defineConfig } from "vitest/config";

export default defineConfig({
  // Relative asset paths, so `dist/` also serves from a subpath. Note that a
  // `file://` open still will not run: browsers refuse module scripts there, so
  // the built page needs a server (`pnpm preview`) like any ES-module bundle.
  base: "./",
  server: { port: 5173 },
  build: { target: "es2022", outDir: "dist" },
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
  },
});
