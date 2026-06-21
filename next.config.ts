import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  webpack: (config, { dev }) => {
    if (dev) {
      // Required for hot reload inside Docker on Windows/WSL2
      // inotify events don't propagate into containers — use polling instead
      config.watchOptions = {
        poll: 600,          // check for changes every 300ms
        aggregateTimeout: 200,
      };
    }
    return config;
  },
};

export default nextConfig;
