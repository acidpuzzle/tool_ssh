# -*- coding: utf-8 -*-
import os
import asyncio
import logging
from datetime import datetime
from ipaddress import ip_address
from scrapli import AsyncScrapli
from scrapli.exceptions import *
from asyncssh import KeyExchangeFailed, ConnectionLost

from old_orm_db_model import *


"""Enable logging"""
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(name)s - %(funcName)s() - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def _scrapli_dev(device_ip: str, **kwargs) -> dict:
    """

    :param device_ip:
    :param kwargs:
    :return:
    """
    try:
        """ If the database has the following entry: "192.168.1.1:22" """
        device_ip = str(ip_address(device_ip.strip(":22")))

        username, password, enable_pass = os.environ.get("CISCO_CREDS").split(':')
        params = {
            'host': device_ip,
            'auth_username': username,
            'auth_password': password,
            'auth_secondary': enable_pass,
            'auth_strict_key': False,
            'timeout_socket': 300,
            'timeout_transport': 30,
            'platform': 'cisco_iosxe',
            'transport': 'asyncssh',
        }
        params.update(kwargs)
        return params

    except (ValueError, TypeError) as error:
        logger.error(error)


async def send_show(device, command):
    try:
        async with AsyncScrapli(**_scrapli_dev(device.ip)) as conn:
            out = await conn.send_command(command)
            return out.result
    except (
            ScrapliException,
            KeyExchangeFailed,
            ScrapliAuthenticationFailed,
            ConnectionLost,
            ConnectionRefusedError,
            OSError,
            TypeError,
    ) as error:
        logger.error(error)


async def send_command_to_devices(devices, commands):
    coroutines = [send_show(device, commands) for device in devices]
    result = await asyncio.gather(*coroutines)
    return result


if __name__ == "__main__":
    start = datetime.now()
    old_routers = old_db_session.query(OldRouter).all()
    old_switches = old_db_session.query(OldSwitch).all()
    # one_old_router = old_db_session.query(OldRouter).filter_by(id=292).first()
    if os.name == 'nt':
        loop = asyncio.ProactorEventLoop()  # for subprocess' pipes on Windows
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()

    result = loop.run_until_complete(send_command_to_devices(old_routers, "sh clock"))
    print(result)
    print(len(result))
    i = 0
    for res in result:
        if res:
            i += 1
    print(f"Not None = {i}")
    print(datetime.now() - start)
