import fs from 'node:fs';
import path from 'node:path';
import 'dotenv/config';
import { OdezzyConfigSchema, OdezzyConfig } from '../types/index.js';

/**
 * Validates raw configuration data against the Zod schema.
 * @param configData The raw configuration data to validate
 * @returns Parsed and validated config
 * @throws Error if validation fails
 */
export function validateConfig(configData: unknown): OdezzyConfig {
  const result = OdezzyConfigSchema.safeParse(configData);
  if (!result.success) {
    const errors = result.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
    throw new Error(`Configuration validation failed: ${errors}`);
  }
  return result.data;
}

/**
 * Loads configuration by merging environment variables and the optional odezzy.config.json file.
 * Defaults are applied via the Zod schema during validation.
 * @returns The final merged and validated configuration
 */
export function loadConfig(): OdezzyConfig {
  const configPath = path.resolve(process.cwd(), 'odezzy.config.json');
  let fileConfig: Record<string, unknown> = {};

  if (fs.existsSync(configPath)) {
    try {
      const fileContent = fs.readFileSync(configPath, 'utf8');
      fileConfig = JSON.parse(fileContent);
    } catch (error) {
      throw new Error(`Failed to parse odezzy.config.json: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Merge env variables with file config (Env takes precedence for secrets)
  const mergedConfig = {
    ...fileConfig,
    geminiApiKey: process.env.GEMINI_API_KEY || fileConfig.geminiApiKey,
    gcpProjectId: process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || fileConfig.gcpProjectId,
    gcpLocation: process.env.GOOGLE_CLOUD_LOCATION || process.env.GCP_LOCATION || fileConfig.gcpLocation,
    remediationMcpServerName: process.env.REMEDIATION_MCP_SERVER_NAME || fileConfig.remediationMcpServerName,
    trueforgeUrl: process.env.TRUEFORGE_URL || fileConfig.trueforgeUrl,
    trueforgeApiKey: process.env.TRUEFORGE_API_KEY || fileConfig.trueforgeApiKey,
    trueforgeModel: process.env.TRUEFORGE_MODEL || fileConfig.trueforgeModel,
  };

  return validateConfig(mergedConfig);
}