import winston from 'winston';
import chalk from 'chalk';
import path from 'node:path';
import fs from 'node:fs';

// Ensure logs directory exists
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

/**
 * Custom console formatter for colorful output using chalk
 */
const consoleFormat = winston.format.printf(({ level, message, timestamp, module }) => {
  const ts = chalk.gray(timestamp);
  const mod = chalk.blue(`[${module}]`);
  
  let coloredLevel = level;
  switch (level) {
    case 'error': coloredLevel = chalk.red(level.toUpperCase()); break;
    case 'warn': coloredLevel = chalk.yellow(level.toUpperCase()); break;
    case 'info': coloredLevel = chalk.green(level.toUpperCase()); break;
    case 'debug': coloredLevel = chalk.magenta(level.toUpperCase()); break;
    case 'trace': coloredLevel = chalk.gray(level.toUpperCase()); break;
    default: coloredLevel = level.toUpperCase();
  }

  return `${ts} ${coloredLevel} ${mod}: ${message}`;
});

/**
 * Creates a structured logger for a specific module
 * @param moduleName Name of the module creating the logger
 * @returns Winston logger instance
 */
export function createLogger(moduleName: string): winston.Logger {
  return winston.createLogger({
    level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
    defaultMeta: { module: moduleName },
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
          consoleFormat
        )
      }),
      new winston.transports.File({
        filename: path.join(logDir, 'odezzy.log'),
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        )
      })
    ]
  });
}
