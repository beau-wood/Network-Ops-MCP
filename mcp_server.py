#!/usr/bin/env python3
"""
Simple FastMCP Server with example tools
Install dependencies: pip install fastmcp
"""

from fastmcp import FastMCP
import datetime

from tools.network import register_network_tools

# Create FastMCP server instance
mcp = FastMCP("Simple MCP Server")

register_network_tools(mcp)


# Run the server
if __name__ == "__main__":
    mcp.run()