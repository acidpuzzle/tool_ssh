# -*- coding: utf-8 -*-
import logging
import os

from netmiko import *
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def netmiko_dev(*,
                device_type: str,
                device_ip: str,
                username: str = None,
                password: str = None,
                enable_pass: str = "cisco",
                env_var: str = None,
                ) -> dict:
    """
    :param device_type: Netmiko platform, example "cisco_ios", "huawei", "cisco_ios_telnet"
           Netmiko supported platforms look at https://github.com/ktbyers/netmiko
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :param username:
    :param password:
    :param enable_pass:
    :param env_var:
    :return: Dictionary with device connection parameters
    """
    if env_var:
        username, password, enable_pass = os.environ.get(env_var).split(':')
    return {
        'device_type': device_type,
        'host': device_ip,
        'username': username,
        'password': password,
        'secret': enable_pass,
    }


def cisco_ios_ssh(device_ip: str, **kwargs) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_type="cisco_ios", device_ip=device_ip, **kwargs)


def cisco_ios_telnet(device_ip: str, **kwargs) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_type="cisco_ios_telnet", device_ip=device_ip, **kwargs)


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
            ssh.save_config()
            return out
    except (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
            ReadTimeout,
            AttributeError,
    ) as err:
        logger.error(err.__str__)


def run_in_threads(worker, max_thread=60, *args):
    """
    len(all_devices) == len(all_commands) = True
    :param worker: a function that will run in threads
    :param max_thread: Maximum number of threads
    :return:
    """
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        results = executor.map(worker, *args)

    return results

