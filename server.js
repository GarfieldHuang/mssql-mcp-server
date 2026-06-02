#!/usr/bin/env node
import 'dotenv/config'
import sql from 'mssql'
import http from 'http'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js'
import { z } from 'zod'
import { createHmac } from 'crypto'

const API_KEY = process.env.API_KEY
const JWT_SECRET = process.env.JWT_SECRET
const HTTP_PORT = Number(process.env.HTTP_PORT) || 3000
const USE_HTTP = process.argv.includes('--http')

if (!API_KEY) { console.error('ERROR: API_KEY not set in .env'); process.exit(1) }
if (USE_HTTP && !JWT_SECRET) { console.error('ERROR: JWT_SECRET not set in .env'); process.exit(1) }

const dbConfig = {
  server: process.env.DB_SERVER,
  port: Number(process.env.DB_PORT) || 1433,
  database: process.env.DB_DATABASE,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  options: { encrypt: false, trustServerCertificate: true },
  pool: { max: 5, min: 0, idleTimeoutMillis: 30000 },
}

let pool

async function getPool() {
  if (!pool) pool = await sql.connect(dbConfig)
  return pool
}

// ── 安全驗證 ──────────────────────────────────────────────
/**
 * TODO: 實作你的 query 安全規則。
 *
 * 有兩種策略，選一個：
 *
 * 策略 A（寬鬆）— 只封鎖危險關鍵字，允許任意 SELECT：
 *   - 適合：schema 複雜、agent 需要自由探索
 *   - 風險：agent 可能 SELECT 到敏感欄位（密碼、個資）
 *
 * 策略 B（嚴格）— 只允許白名單內的特定操作：
 *   - 適合：已知 agent 只會做哪幾件事
 *   - 好處：即使 agent 被 prompt injection，也打不到其他 table
 *
 * @param {string} query
 * @returns {{ ok: boolean, reason?: string }}
 */
function validateQuery(query) {
  // TODO: 在這裡實作你的驗證邏輯（5-10 行）
  // 以下是最基本的防護，請根據你的需求加強：

  const normalized = query.trim().toLowerCase()

  // 只允許 SELECT 開頭
  if (!normalized.startsWith('select')) {
    return { ok: false, reason: 'Only SELECT queries are allowed' }
  }

  // 封鎖寫入 / 系統操作關鍵字
  const blocked = [
    'insert', 'update', 'delete', 'drop', 'truncate', 'alter', 'create',
    'exec', 'execute', 'xp_', 'sp_',          // stored procedure / shell
    'openrowset', 'opendatasource', 'bulk',    // 外部資料存取
    'into outfile', 'load_file',               // 檔案操作
    ';',                                        // 防止 stacked queries
  ]
  for (const keyword of blocked) {
    if (normalized.includes(keyword)) {
      return { ok: false, reason: `Blocked keyword: ${keyword}` }
    }
  }

  // 限制單次回傳筆數，避免 agent 把整張大表撈出來
  if (!normalized.includes('top ') && !normalized.includes('where')) {
    return { ok: false, reason: 'Query must include TOP or WHERE to limit result size' }
  }

  return { ok: true }
}
// ─────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'mssql-readonly',
  version: '1.0.0',
})

server.tool(
  'query',
  'Run a read-only SQL SELECT query against the database',
  {
    sql: z.string().describe('The SELECT query to execute'),
    api_key: z.string().describe('API key for authentication'),
  },
  async ({ sql: queryStr, api_key }) => {
    if (api_key !== API_KEY) {
      return { content: [{ type: 'text', text: 'Error: Invalid API key' }], isError: true }
    }

    const check = validateQuery(queryStr)
    if (!check.ok) {
      return { content: [{ type: 'text', text: `Error: ${check.reason}` }], isError: true }
    }

    try {
      const db = await getPool()
      const result = await db.request().query(queryStr)
      const output = JSON.stringify(result.recordset, null, 2)
      console.error(`[query] rows=${result.recordset.length} sql="${queryStr.slice(0, 80)}"`)
      return { content: [{ type: 'text', text: output }] }
    } catch (err) {
      console.error(`[query error] ${err.message}`)
      return { content: [{ type: 'text', text: `DB Error: ${err.message}` }], isError: true }
    }
  }
)

server.tool(
  'list_tables',
  'List all tables in the database',
  { api_key: z.string() },
  async ({ api_key }) => {
    if (api_key !== API_KEY) {
      return { content: [{ type: 'text', text: 'Error: Invalid API key' }], isError: true }
    }
    try {
      const db = await getPool()
      const result = await db.request().query(
        "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_SCHEMA, TABLE_NAME"
      )
      return { content: [{ type: 'text', text: JSON.stringify(result.recordset, null, 2) }] }
    } catch (err) {
      return { content: [{ type: 'text', text: `DB Error: ${err.message}` }], isError: true }
    }
  }
)

server.tool(
  'describe_table',
  'Show columns and types for a specific table',
  { table: z.string(), api_key: z.string() },
  async ({ table, api_key }) => {
    if (api_key !== API_KEY) {
      return { content: [{ type: 'text', text: 'Error: Invalid API key' }], isError: true }
    }
    // Prevent injection in table name
    if (!/^[\w\.\[\]]+$/.test(table)) {
      return { content: [{ type: 'text', text: 'Error: Invalid table name' }], isError: true }
    }
    try {
      const db = await getPool()
      const result = await db.request().query(
        `SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH
         FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '${table}' ORDER BY ORDINAL_POSITION`
      )
      return { content: [{ type: 'text', text: JSON.stringify(result.recordset, null, 2) }] }
    } catch (err) {
      return { content: [{ type: 'text', text: `DB Error: ${err.message}` }], isError: true }
    }
  }
)

// ── JWT 驗證（HTTP 模式用）────────────────────────────────
function verifyJwt(authHeader) {
  if (!authHeader?.startsWith('Bearer ')) return false
  const token = authHeader.slice(7)
  const [headerB64, payloadB64, sig] = token.split('.')
  if (!headerB64 || !payloadB64 || !sig) return false
  const expected = createHmac('sha256', JWT_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64url')
  if (sig !== expected) return false
  const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString())
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return false
  return true
}
// ─────────────────────────────────────────────────────────

if (USE_HTTP) {
  const httpServer = http.createServer(async (req, res) => {
    if (req.method === 'POST' && req.url === '/mcp') {
      if (!verifyJwt(req.headers['authorization'])) {
        res.writeHead(401, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Unauthorized' }))
        return
      }
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined })
      await server.connect(transport)
      await transport.handleRequest(req, res)
    } else {
      res.writeHead(404)
      res.end()
    }
  })
  httpServer.listen(HTTP_PORT, () => {
    console.error(`[mssql-mcp] HTTP mode, listening on port ${HTTP_PORT}`)
  })
} else {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  console.error('[mssql-mcp] Stdio mode, waiting for connections...')
}
