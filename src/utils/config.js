'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Default configuration — these are used when no .beaverguardrc.json is found.
 */
const DEFAULT_CONFIG = {
  entropy_threshold: 5.6,
  max_file_size_kb: 512,
  osv_timeout_ms: 8000,
  trusted_packages: [],
  trusted_scopes: [],
  skip_dirs: [],
};

/**
 * Load .beaverguardrc.json from cwd, walking up to repo root (max 3 levels).
 * Merges user config with defaults — arrays are concatenated, never replaced.
 * Returns the merged config or defaults if file not found.
 * @returns {object} merged config
 */
function loadConfig() {
  const defaults = JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  let searchDir = process.cwd();
  const maxLevels = 3;

  for (let i = 0; i < maxLevels; i++) {
    const configPath = path.join(searchDir, '.beaverguardrc.json');
    if (fs.existsSync(configPath)) {
      try {
        const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        return {
          entropy_threshold: userConfig.entropy_threshold ?? defaults.entropy_threshold,
          max_file_size_kb: userConfig.max_file_size_kb ?? defaults.max_file_size_kb,
          osv_timeout_ms: userConfig.osv_timeout_ms ?? defaults.osv_timeout_ms,
          trusted_packages: [
            ...defaults.trusted_packages,
            ...(userConfig.trusted_packages || []),
          ],
          trusted_scopes: [
            ...defaults.trusted_scopes,
            ...(userConfig.trusted_scopes || []),
          ],
          skip_dirs: [
            ...defaults.skip_dirs,
            ...(userConfig.skip_dirs || []),
          ],
        };
      } catch (e) {
        console.warn(`Warning: .beaverguardrc.json at ${configPath} is invalid JSON — using defaults`);
        return defaults;
      }
    }
    const parent = path.dirname(searchDir);
    if (parent === searchDir) break;
    searchDir = parent;
  }

  return defaults;
}

module.exports = { loadConfig, DEFAULT_CONFIG };
