import fs from 'fs/promises';
import path from 'path';
import { 
  type OdezzyConfig, 
  DiscoveryResultSchema, 
  type MCPServerInventory,
  type DiscoveryResult,
} from '../types/index.js';
import { MCPConnector, ServerConfig } from './mcp-connector.js';
import { createLogger } from '../utils/logger.js';

const logger = createLogger('inventory-builder');

export class InventoryBuilder {
  private config: OdezzyConfig;
  private inventory: DiscoveryResult | null = null;
  private maxConcurrency: number;

  constructor(config: OdezzyConfig) {
    this.config = config;
    this.maxConcurrency = config.scanOptions?.maxConcurrency ?? 3;
  }

  /**
   * Connects to all configured servers, collects tools, returns full inventory.
   */
  public async buildInventory(): Promise<DiscoveryResult> {
    logger.info('Starting inventory build');
    const servers = (this.config.servers as ServerConfig[]) || [];
    if (servers.length === 0) {
      logger.warn('No servers configured');
      return this.createEmptyResult();
    }

    const serverInventories: MCPServerInventory[] = [];
    const pool = new Set<Promise<void>>();

    for (const server of servers) {
      const p = this.scanServerWithRetry(server).then(inventory => {
        if (inventory) {
          serverInventories.push(inventory);
        }
      }).catch(err => {
        logger.error(`Unhandled error scanning server ${server.name}`, err);
      }).finally(() => {
        pool.delete(p);
      });

      pool.add(p);

      if (pool.size >= this.maxConcurrency) {
        await Promise.race(pool);
      }
    }

    await Promise.all(pool);

    let totalTools = 0;
    for (const inv of serverInventories) {
      totalTools += inv.tools.length;
    }

    const result = {
      servers: serverInventories,
      totalTools,
      timestamp: new Date().toISOString(),
    };

    const validatedResult = DiscoveryResultSchema.parse(result);
    this.inventory = validatedResult;

    await this.saveToDisk(validatedResult);

    return validatedResult;
  }

  /**
   * Scans a single server.
   */
  public async scanServer(serverConfig: ServerConfig): Promise<MCPServerInventory> {
    logger.info(`Scanning server: ${serverConfig.name}`);
    const connector = new MCPConnector(serverConfig, { timeoutMs: this.config.scanOptions?.timeoutMs });
    
    try {
      await connector.connect();
      const tools = await connector.listTools();
      const serverInfo = connector.getServerInfo();
      
      const inventory: MCPServerInventory = {
        serverName: serverInfo.name,
        serverVersion: serverInfo.version,
        transport: 'stdio',
        tools: tools,
        scannedAt: new Date().toISOString(),
        connectionUri: serverConfig.command,
      };
      
      return inventory;
    } finally {
      await connector.disconnect();
    }
  }

  /**
   * Retry logic for server scanning.
   */
  private async scanServerWithRetry(serverConfig: ServerConfig, attempts = 3): Promise<MCPServerInventory | null> {
    for (let i = 1; i <= attempts; i++) {
      try {
        return await this.scanServer(serverConfig);
      } catch (error) {
        logger.warn(`Attempt ${i} failed for server ${serverConfig.name}`);
        if (i === attempts) {
          logger.error(`All ${attempts} attempts failed for server ${serverConfig.name}`);
          return null;
        }
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
      }
    }
    return null;
  }

  /**
   * Returns last built inventory.
   */
  public getInventory(): DiscoveryResult | null {
    return this.inventory;
  }

  private async saveToDisk(result: DiscoveryResult): Promise<void> {
    try {
      const inventoryPath = path.resolve(process.cwd(), '.odezzy', 'inventory.json');
      await fs.mkdir(path.dirname(inventoryPath), { recursive: true });
      await fs.writeFile(inventoryPath, JSON.stringify(result, null, 2));
      logger.info(`Inventory saved to ${inventoryPath}`);
    } catch (error) {
      logger.error('Failed to save inventory to disk', error);
    }
  }

  private createEmptyResult(): DiscoveryResult {
    return {
      servers: [],
      totalTools: 0,
      timestamp: new Date().toISOString(),
    };
  }
}
