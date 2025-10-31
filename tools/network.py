#!/usr/bin/env python3
"""
Network Tools for MCP
"""
from __future__ import annotations
import ipaddress
import platform
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Dict, Optional



def register_network_tools(mcp):

    @mcp.tool()
    def get_network_configs() -> dict[str, str]:
        """
        Get all network configurations for local network.  This uses the command line tool ifconfig.

        Returns:
            A dictionary with keys of 'status' and 'network_configs'.  If the status is 'error', the network_configs will
            have information on the error.  If the status is 'success', the network_configs will have information on the local
            network configuration.

        """
        try:
            out = subprocess.run('ifconfig', capture_output=True, text=True, check=False)
            return {'status': 'success', 'network_configs': out.stdout}
        except Exception as e:
            return {'status': 'error', 'network_configs': str(e)}



    @mcp.tool()
    def scan_ports(host: str,
                   ports: List[int] = None,
                   port_range: tuple[int, int] = None,
                   timeout_seconds: float = 0.5,
                   max_workers: int = 200) -> Dict[str, object]:
        """
        Perform a TCP connect-style port scan against a single host.

        This is a simple TCP SYN/CONNECT-style scanner that attempts a full TCP
        connect to each port provided. It is intentionally non-aggressive and meant
        for enumeration on hosts you control. It does not attempt exploitation.

        Parameters
        ----------
        host:
            Target host as an IPv4 address or hostname (string).
        ports:
            An optional iterable of integer ports to probe (e.g., [22, 80, 443]).
            If omitted, supply `port_range`.
        port_range:
            Optional inclusive port range as (start_port, end_port) to scan.
            Example: (1, 1024). If both `ports` and `port_range` are provided,
            `ports` takes precedence.
        timeout_seconds:
            Socket connect timeout per port in seconds (float).
        max_workers:
            Maximum number of concurrent worker threads.

        Returns
        -------
        dict:
            JSON-serializable dictionary with fields:
              - "target" (str): resolved target string
              - "open_ports" (list[int]): list of ports that accepted a TCP connection
              - "closed_or_filtered" (list[int]): list of probed ports that did not accept a connection
              - "errors" (list[str]): non-fatal error messages encountered during scanning
            Example:
              {
                "target": "192.168.1.42",
                "open_ports": [22, 80],
                "closed_or_filtered": [23, 25, 110],
                "errors": []
              }

        Raises
        ------
        ValueError:
            If neither `ports` nor `port_range` is provided, or invalid port numbers are given.

        Notes for FastMCP / LLM integration
        ----------------------------------
        - The function returns JSON-serializable output appropriate for MCP responses.
        - Use only on hosts you own or have permission to test.
        - Connecting to a large number of ports or scanning remote networks may trigger IDS/IPS.
        """
        # Input validation and port list creation
        if ports is None and port_range is None:
            raise ValueError("either 'ports' or 'port_range' must be provided")

        # Normalize ports iterable
        if ports is not None:
            # Convert to a list and validate
            ports_list = [int(p) for p in ports]
        else:
            start, end = port_range
            if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                raise ValueError("invalid port_range; ports must be between 1 and 65535")
            ports_list = list(range(start, end + 1))

        # Thread worker for probing a single port
        def probe(port: int) -> tuple[int, bool, Optional[str]]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout_seconds)
                    s.connect((host, port))
                    # Success: remote accepted connection
                    return (port, True, None)
            except Exception as exc:
                # Return False and the exception text for non-fatal errors
                return (port, False, str(exc))

        open_ports: List[int] = []
        closed_or_filtered: List[int] = []
        errors: List[str] = []

        with ThreadPoolExecutor(max_workers=max_workers) as exe:
            futures = {exe.submit(probe, p): p for p in ports_list}
            for fut in as_completed(futures):
                try:
                    port, is_open, err = fut.result()
                    if is_open:
                        open_ports.append(port)
                    else:
                        closed_or_filtered.append(port)
                        if err:
                            # Keep a short error message; de-duplicate later
                            errors.append(f"port {port}: {err}")
                except Exception as exc:
                    p = futures[fut]
                    closed_or_filtered.append(p)
                    errors.append(f"port {p}: unexpected error {exc}")

        open_ports.sort()
        closed_or_filtered.sort()
        # Deduplicate errors
        errors = list(dict.fromkeys(errors))

        return {
            "target": host,
            "open_ports": open_ports,
            "closed_or_filtered": closed_or_filtered,
            "errors": errors
        }


