import { ProbeCallResult } from '../types/index.js';

/**
 * Normalizes raw probe output into the shape expected by analyzers (e.g. SchemaDiffAnalyzer).
 */
export class ProbeResultNormalizer {
  public static normalize(
    toolName: string, 
    serverName: string, 
    sentArgs: Record<string, any>, 
    callSucceeded: boolean, 
    rawResponse: unknown
  ): ProbeCallResult {
    const sentArgKeys = Object.keys(sentArgs);
    const responseText = typeof rawResponse === 'string' ? rawResponse : JSON.stringify(rawResponse);
    
    // Simple heuristic to check if the extra arg was echoed back
    // This is useful for undeclared-param-probe to know if the arg was actually processed
    let responseContainsArgEcho = false;
    for (const val of Object.values(sentArgs)) {
      if (typeof val === 'string' && val.length > 3 && responseText.includes(val)) {
        responseContainsArgEcho = true;
        break;
      }
    }

    return {
      toolName,
      serverName,
      sentArgKeys,
      callSucceeded,
      responseText,
      responseContainsArgEcho,
    };
  }
}
