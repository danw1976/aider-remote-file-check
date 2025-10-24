#!/usr/bin/env python3
"""
Remote server inode usage checker.

Connects to a remote server via SSH and lists directories with their inode usage.
"""

import argparse
import sys
from pathlib import Path

import paramiko


def get_ssh_client(
    host: str, username: str, password: str = None, key_file: str = None, port: int = 22
) -> paramiko.SSHClient:
    """
    Create and return an SSH client connected to the remote server.

    Args:
        host: Remote server hostname or IP address
        username: SSH username
        password: SSH password (optional if using key_file)
        key_file: Path to SSH private key file (optional if using password)
        port: SSH port (default: 22)

    Returns:
        Connected SSHClient instance

    Raises:
        paramiko.AuthenticationException: If authentication fails
        paramiko.SSHException: If SSH connection fails
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        if key_file:
            client.connect(host, port=port, username=username, key_filename=key_file)
        else:
            client.connect(host, port=port, username=username, password=password)
    except (paramiko.AuthenticationException, paramiko.SSHException) as e:
        print(f"Error: Failed to connect to {host}: {e}", file=sys.stderr)
        sys.exit(1)

    return client


def get_directory_inodes(client: paramiko.SSHClient, path: str) -> dict:
    """
    Get inode usage for each directory at the given path.

    Args:
        client: Connected SSHClient instance
        path: Remote path to check

    Returns:
        Dictionary mapping directory names to inode counts

    Raises:
        RuntimeError: If the remote command fails
    """
    # Use 'du' with inode information
    # The command lists directories and their inode usage
    cmd = f'find \'{path}\' -maxdepth 1 -type d -exec sh -c \'echo "{{}}" $(find "{{}}" -printf "%i\\n" | wc -l)\' \\;'

    try:
        stdin, stdout, stderr = client.exec_command(cmd)
        error_output = stderr.read().decode().strip()

        if error_output:
            print(f"Warning: {error_output}", file=sys.stderr)

        output = stdout.read().decode().strip()

        if not output:
            raise RuntimeError(
                f"No output from remote command or path does not exist: {path}"
            )

        result = {}
        for line in output.split("\n"):
            if line.strip():
                parts = line.rsplit(" ", 1)
                if len(parts) == 2:
                    dir_path, inode_count = parts
                    dir_name = Path(dir_path).name or dir_path
                    try:
                        result[dir_name] = int(inode_count)
                    except ValueError:
                        continue

        return result

    except Exception as e:
        raise RuntimeError(f"Failed to execute remote command: {e}")


def main():
    """Main entry point for the inode checker."""
    parser = argparse.ArgumentParser(
        description="List directories and their inode usage on a remote server"
    )
    parser.add_argument("host", help="Remote server hostname or IP address")
    parser.add_argument("path", help="Remote path to check")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", help="SSH password (if not using key)")
    parser.add_argument("-k", "--key", help="Path to SSH private key file")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    args = parser.parse_args()

    if not args.password and not args.key:
        print("Error: Either --password or --key must be provided", file=sys.stderr)
        sys.exit(1)

    # Connect to remote server
    print(f"Connecting to {args.host}...", file=sys.stderr)
    client = get_ssh_client(
        args.host, args.username, args.password, args.key, args.port
    )

    try:
        # Get directory inode usage
        print(f"Checking inode usage in {args.path}...", file=sys.stderr)
        inodes = get_directory_inodes(client, args.path)

        if not inodes:
            print("No directories found.", file=sys.stderr)
            return

        # Sort by inode count (descending)
        sorted_inodes = sorted(inodes.items(), key=lambda x: x[1], reverse=True)

        # Print results
        print("\nDirectory Inode Usage:")
        print("-" * 50)
        print(f"{'Directory':<40} {'Inodes':>8}")
        print("-" * 50)

        for dir_name, inode_count in sorted_inodes:
            print(f"{dir_name:<40} {inode_count:>8}")

        print("-" * 50)
        print(f"{'Total':<40} {sum(inodes.values()):>8}")

    finally:
        client.close()


if __name__ == "__main__":
    main()
