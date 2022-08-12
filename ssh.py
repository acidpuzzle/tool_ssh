# -*- coding: utf-8 -*-
import logging

from netmiko import *
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor


logger = logging.getLogger(__name__)


def netmiko_dev(*,
                device_type: str,
                device_ip: str,
                username: str = None,
                password: str = None,
                enable_pass: str = "cisco",
                ) -> dict:
    """
    :param device_type: Netmiko platform, example "cisco_ios", "huawei", "cisco_ios_telnet"
           Netmiko supported platforms look at https://github.com/ktbyers/netmiko
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :param username:
    :param password:
    :param enable_pass:
    :return: Dictionary with device connection parameters
    """
    return {
        'device_type': device_type,
        'host': device_ip,
        'username': username,
        'password': password,
        'secret': enable_pass,
    }


def get_config(device: dict, command: str) -> str:
    """
    Get configuration from network device
    -------------------------------------
    :param device: Dictionary with connection parameters
    :param command: String, one `show` command
    :return:
    """
    logger.debug(f"Send {command=} to {device['host']}")
    try:
        with ConnectHandler(**device) as ssh:
            out = ssh.send_command(command)
            logger.debug(f"Out {out} from {command} in {device['host']}")
            return out
    except (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
            ReadTimeout,
            AttributeError,
    ) as err:
        logger.error(err.__str__)


def send_config(device: dict, commands: list) -> str:
    """
    Send configuration to network device
    :param device: Dictionary with connection parameters
    :param commands: List of configuration commands
    :return: None
    """
    logger.debug(f"Send {commands=} to {ip_address}")
    try:
        with ConnectHandler(**device) as ssh:
            out = ssh.send_config_set(commands)
            return out
    except (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
            ReadTimeout,
            AttributeError,
    ) as err:
        logger.error(err.__str__)


def run_in_threads(worker, max_thread=60, *args, **kwargs):
    """
    len(all_devices) == len(all_commands) = True
    :param worker: a function that will run in threads
    :param max_thread: Maximum number of threads
    :return:
    """
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        results = executor.map(worker, *args, **kwargs)

    return results

