#!/usr/bin/env python3
"""
Bot token management script for Bot-Command.
Manages bot tokens in MongoDB for the monitoring system.
"""

import asyncio
import logging
import os
import sys
import json
from typing import Optional

import typer
import aiohttp
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from telethon import TelegramClient

from src.storage.mongo_client import MongoDBManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Typer app
app = typer.Typer(help="Manage bot tokens for monitoring")
console = Console()

def cleanup_client(client: Optional[TelegramClient], session_name: str):
    """Clean up the client connection and session file."""
    if client:
        try:
            client.disconnect()  # Use synchronous disconnect
        except Exception:
            pass
            
    try:
        session_file = f"{session_name}.session"
        if os.path.exists(session_file):
            os.remove(session_file)
    except Exception:
        pass

async def verify_bot_token(api_id: int, api_hash: str, token: str) -> tuple[Optional[str], str]:
    """
    Verify a bot token and get its status.
    
    Args:
        api_id: Telegram API ID
        api_hash: Telegram API hash
        token: Bot token to verify
        
    Returns:
        Tuple of (username, status). Username might be None if unavailable.
        Status will be one of: 'active', 'logged_out', 'invalid', 'unauthorized'
    """
    # Use a unique session name for each verification attempt
    session_name = f"temp_verify_{token.split(':')[0]}"
    client = None
    try:
        # First check with Telegram API directly
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.telegram.org/bot{token}/getMe") as response:
                result = await response.text()
                data = json.loads(result)
                if not data.get('ok', False):
                    error_msg = data.get('description', '').lower()
                    if 'unauthorized' in error_msg:
                        return None, 'unauthorized'
                    elif 'logged' in error_msg:
                        return None, 'logged_out'
                    else:
                        return None, 'invalid'
                username = data['result'].get('username')
                return username, 'active'
                
    except Exception as e:
        logger.error(f"Failed to verify bot token: {str(e)}")
        return None, 'invalid'
    finally:
        # Clean up client if it exists and is connected
        if client and hasattr(client, 'is_connected') and client.is_connected():
            try:
                client.disconnect()  # Use synchronous disconnect
            except Exception:
                pass
                
        # Clean up session file
        try:
            session_file = f"{session_name}.session"
            if os.path.exists(session_file):
                os.remove(session_file)
        except Exception:
            pass

@app.command()
def add(token: str):
    """Add a new bot token to monitor."""
    async def _add():
        # Load environment variables
        load_dotenv()
        
        # Get API credentials
        api_id = os.getenv("TELEGRAM_API_ID")
        api_hash = os.getenv("TELEGRAM_API_HASH")
        
        if not api_id or not api_hash:
            console.print("[red]Error:[/red] TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env file")
            sys.exit(1)

        # Verify the token and get status
        with console.status("Verifying bot token..."):
            username, status = await verify_bot_token(int(api_id), api_hash, token)
            
        if username is None:
            console.print(f"[yellow]Warning:[/yellow] Bot token verification returned status: {status}")
            username = f"unknown_bot_{token.split(':')[0]}"  # Use bot ID as temporary username
            
        # Add to MongoDB
        mongo = MongoDBManager()
        try:
            with console.status("Adding bot to database..."):
                success = await mongo.add_bot_token(token, username, status=status)
                
            if success:
                status_color = "green" if status == "active" else "yellow"
                console.print(f"[{status_color}]Success:[/{status_color}] Added bot @{username} to monitoring (Status: {status})")
            else:
                console.print("[yellow]Notice:[/yellow] Bot token already exists in database")
        finally:
            mongo.close()
            
    asyncio.run(_add())

@app.command()
def remove(token: str):
    """Remove a bot token from monitoring."""
    async def _remove():
        mongo = MongoDBManager()
        try:
            with console.status("Removing bot from database..."):
                info = await mongo.get_bot_info(token=token)
                if info:
                    success = await mongo.remove_bot_token(token)
                    if success:
                        console.print(f"[green]Success:[/green] Removed bot @{info.get('username', 'unknown')} from monitoring")
                    else:
                        console.print("[red]Error:[/red] Failed to remove bot token")
                else:
                    console.print("[yellow]Notice:[/yellow] Bot token not found in database")
        finally:
            mongo.close()
            
    asyncio.run(_remove())

@app.command()
def list():
    """List all monitored bot tokens."""
    async def _list():
        mongo = MongoDBManager()
        try:
            # Create table
            table = Table(show_header=True, header_style="bold")
            table.add_column("Username")
            table.add_column("Token")
            table.add_column("Status")
            table.add_column("Failures")
            table.add_column("Last Success")
            
            # Get all bots
            cursor = mongo.monitored_bots.find()
            async for bot in cursor:
                username = bot.get('username', 'unknown')
                token = bot.get('token', 'unknown')
                status = bot.get('status', 'unknown')
                failures = str(bot.get('failure_count', 0))
                last_success = bot.get('last_success')
                last_success_str = last_success.strftime('%Y-%m-%d %H:%M:%S') if last_success else 'never'
                
                # Color-code status
                if status == 'active':
                    status = f"[green]{status}[/green]"
                elif status == 'inactive':
                    status = f"[red]{status}[/red]"
                    
                table.add_row(
                    f"@{username}",
                    token,
                    status,
                    failures,
                    str(last_success_str)
                )
                
            console.print(table)
        finally:
            mongo.close()
            
    asyncio.run(_list())

@app.command()
def activate(token: str):
    """Activate a bot token for monitoring."""
    async def _activate():
        mongo = MongoDBManager()
        try:
            with console.status("Activating bot..."):
                info = await mongo.get_bot_info(token=token)
                if info:
                    success = await mongo.update_bot_status(token, status="active")
                    if success:
                        console.print(f"[green]Success:[/green] Activated bot @{info.get('username', 'unknown')}")
                    else:
                        console.print("[red]Error:[/red] Failed to activate bot")
                else:
                    console.print("[yellow]Notice:[/yellow] Bot token not found in database")
        finally:
            mongo.close()
            
    asyncio.run(_activate())

@app.command()
def deactivate(token: str):
    """Deactivate a bot token from monitoring."""
    async def _deactivate():
        mongo = MongoDBManager()
        try:
            with console.status("Deactivating bot..."):
                info = await mongo.get_bot_info(token=token)
                if info:
                    success = await mongo.update_bot_status(token, status="inactive")
                    if success:
                        console.print(f"[green]Success:[/green] Deactivated bot @{info.get('username', 'unknown')}")
                    else:
                        console.print("[red]Error:[/red] Failed to deactivate bot")
                else:
                    console.print("[yellow]Notice:[/yellow] Bot token not found in database")
        finally:
            mongo.close()
            
    asyncio.run(_deactivate())

@app.command()
def verify():
    """Verify all stored bot tokens against Telegram API."""
    async def _verify():
        # Load environment variables for API credentials
        load_dotenv()
        api_id = os.getenv("TELEGRAM_API_ID")
        api_hash = os.getenv("TELEGRAM_API_HASH")
        
        if not api_id or not api_hash:
            console.print("[red]Error:[/red] TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env file")
            sys.exit(1)

        mongo = MongoDBManager()
        try:
            # Get all bot tokens
            cursor = mongo.monitored_bots.find({})
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Username")
            table.add_column("Token")
            table.add_column("Current Status")
            table.add_column("API Status")
            table.add_column("Failures")
            table.add_column("Last Success")
            
            async for bot in cursor:
                token = bot.get('token')
                username = bot.get('username', 'unknown')
                current_status = bot.get('status', 'unknown')
                failures = str(bot.get('failure_count', 0))
                last_success = bot.get('last_success')
                last_success_str = last_success.strftime('%Y-%m-%d %H:%M:%S') if last_success else 'never'
                
                # Check token against Telegram API
                with console.status(f"Checking @{username}..."):
                    new_username, new_status = await verify_bot_token(int(api_id), api_hash, token)
                    
                    # Update status in database if it changed
                    if new_status != current_status:
                        if new_status == 'active':
                            await mongo.update_bot_status(token, status=new_status, success=True)
                            if new_username and new_username != username:
                                await mongo.update_bot_status(token, username=new_username)
                                username = new_username
                        else:
                            await mongo.update_bot_status(token, status=new_status, increment_failures=True)
                    
                    # Color code the statuses
                    current_status_color = {
                        'active': '[green]Active[/green]',
                        'logged_out': '[yellow]Logged Out[/yellow]',
                        'unauthorized': '[red]Unauthorized[/red]',
                        'invalid': '[red]Invalid[/red]'
                    }.get(current_status, f'[white]{current_status}[/white]')
                    
                    new_status_color = {
                        'active': '[green]Active[/green]',
                        'logged_out': '[yellow]Logged Out[/yellow]',
                        'unauthorized': '[red]Unauthorized[/red]',
                        'invalid': '[red]Invalid[/red]'
                    }.get(new_status, f'[white]{new_status}[/white]')
                    
                    # Add status change indicator
                    if new_status != current_status:
                        new_status_color += ' [yellow]↻[/yellow]'
                
                table.add_row(
                    f"@{username}",
                    token,
                    current_status_color,
                    new_status_color,
                    failures,
                    str(last_success_str)
                )
            
            console.print(table)
        finally:
            mongo.close()
            
    asyncio.run(_verify())

if __name__ == "__main__":
    app() 