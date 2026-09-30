// Test preload (bunfig.toml): fixes the environment every test assumes, so `bun test` needs no flags.
// Podman addressing keeps tests off the Apple container CLI; the AI provider is on so the panel code runs.
process.env.SEARXNG_RUNTIME = "podman";
process.env.SEARXNG_AI_PROVIDER = "codex";
