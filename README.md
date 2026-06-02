# mssql-mcp-server

A read-only MCP (Model Context Protocol) server for MS SQL Server. Lets AI agents query your database safely — no writes, no stored procedures, no shell access.

## Features

- **Read-only** — only `SELECT` queries allowed
- **Two modes** — stdio (local) or HTTP + JWT (remote)
- **No third-party auth libraries** — JWT verified with Node.js built-in `crypto`
- **Query safety** — blocks dangerous keywords, requires `TOP` or `WHERE`

## Tools exposed to AI agents

| Tool | Description |
|---|---|
| `list_tables` | List all tables in the database |
| `describe_table` | Show columns and types for a table |
| `query` | Run a read-only SELECT query |

## Installation

```bash
npm install
cp .env.example .env
# Fill in your DB credentials and API_KEY
```

## Usage

### Stdio mode (local agent)

```bash
node server.js
```

Configure in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mssql": {
      "command": "node",
      "args": ["/path/to/server.js"]
    }
  }
}
```

### HTTP mode (remote agent)

```bash
node server.js --http
```

Agents connect via:

```http
POST http://your-server:3000/mcp
Authorization: Bearer <jwt-token>
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DB_SERVER` | Yes | MSSQL hostname or IP |
| `DB_PORT` | No | Default: 1433 |
| `DB_DATABASE` | Yes | Database name |
| `DB_USER` | Yes | DB username (use a read-only account) |
| `DB_PASSWORD` | Yes | DB password |
| `API_KEY` | Yes | Secret key agents must pass in tool calls |
| `HTTP_PORT` | No | HTTP mode port, default: 3000 |
| `JWT_SECRET` | HTTP only | Secret for JWT verification |

## Create a read-only DB user (MSSQL)

```sql
CREATE LOGIN mcp_agent WITH PASSWORD = 'strong-password';
CREATE USER mcp_agent FOR LOGIN mcp_agent;
EXEC sp_addrolemember 'db_datareader', 'mcp_agent';
```

## Generate API_KEY

```bash
node -e "const c=require('crypto');console.log(c.randomBytes(32).toString('hex'))"
```
