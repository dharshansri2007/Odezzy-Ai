import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createLogger } from '../utils/logger.js';
import { MCPToolSchemaSchema, type MCPToolSchema } from '../types/index.js';

const logger = createLogger('mcp-connector');

export interface ServerConfig {
  name: string;
  command: string;
  args: string[];
  env?: Record<string, string>;
}

export class MCPConnector {
  private serverConfig: ServerConfig;
  private client: Client;
  private transport: StdioClientTransport | null = null;
  private connectionTimeout: number;
  
  constructor(serverConfig: ServerConfig, opts?: { timeoutMs?: number }) {
    this.serverConfig = serverConfig;
    this.connectionTimeout = opts?.timeoutMs ?? 10000;
    this.client = new Client(
      {
        name: 'odezzy-discovery',
        version: '1.0.0',
      },
      {
        capabilities: {},
      }
    );
  }

  /**
   * Connects to the MCP server.
   */
  public async connect(): Promise<void> {
    logger.info(`Connecting to MCP server ${this.serverConfig.name}`);
    
    const mergedEnv: Record<string, string> = {};
    for (const [key, value] of Object.entries({ ...process.env, ...this.serverConfig.env })) {
      if (value !== undefined) {
        mergedEnv[key] = value;
      }
    }

    this.transport = new StdioClientTransport({
      command: this.serverConfig.command,
      args: this.serverConfig.args,
      env: mergedEnv,
    });
    
    const connectPromise = this.client.connect(this.transport);
    
    const timeoutPromise = new Promise<void>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Connection to server ${this.serverConfig.name} timed out after ${this.connectionTimeout}ms`));
      }, this.connectionTimeout);
    });

    try {
      await Promise.race([connectPromise, timeoutPromise]);
      logger.info(`Successfully connected to ${this.serverConfig.name}`);
    } catch (error) {
      logger.error(`Failed to connect to ${this.serverConfig.name}`, error);
      throw error;
    }
  }

  /**
   * Lists all available tools from the connected MCP server.
   * @returns Array of validated tools
   */
  public async listTools(): Promise<MCPToolSchema[]> {
    logger.info(`Listing tools for ${this.serverConfig.name}`);
    try {
      const response = await this.client.listTools();
      const tools = response.tools.map((tool: any) => {
        return MCPToolSchemaSchema.parse(tool);
      });
      return tools;
    } catch (error) {
      logger.error(`Failed to list tools for ${this.serverConfig.name}`, error);
      throw error;
    }
  }

  /**
   * Calls a specific tool by name.
   */
  public async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    logger.info(`Calling tool ${name} on ${this.serverConfig.name}`);
    try {
      const result = await this.client.callTool({
        name,
        arguments: args,
      });
      return result;
    } catch (error) {
      logger.error(`Failed to call tool ${name} on ${this.serverConfig.name}`, error);
      throw error;
    }
  }

  /**
   * Cleanly disconnects the transport.
   */
  public async disconnect(): Promise<void> {
    logger.info(`Disconnecting from ${this.serverConfig.name}`);
    if (this.transport) {
      try {
        await this.transport.close();
      } catch (error) {
        logger.error(`Error closing transport for ${this.serverConfig.name}`, error);
      }
    }
  }

  /**
   * Retrieves server metadata.
   */
  public getServerInfo(): { name: string; version: string } {
    return {
      name: this.serverConfig.name,
      version: this.client.getServerVersion()?.version || 'unknown',
    };
  }
}
