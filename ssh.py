# -*- coding: utf-8 -*-
import os
import logging

from netmiko import *
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor


logger = logging.getLogger(__name__)


def netmiko_dev(device_type: str, device_ip: str) -> dict:
    """
    :param device_type: Netmiko platform, example "cisco_ios", "huawei", "cisco_ios_telnet"
           Netmiko supported platforms look at https://github.com/ktbyers/netmiko
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :return: Dictionary with device connection parameters
    """
    try:
        # If the database has the following entry: "192.168.1.1:22"
        device_ip = str(ip_address(device_ip.strip(":22")))
        username, password, enable_pass = os.environ.get("CISCO_CREDS").split(':')
        return {
            'device_type': device_type,
            'host': device_ip,
            'username': username,
            'password': password,
            'secret': enable_pass,
        }
    except (ValueError, TypeError) as error:
        logger.error(error)


def cisco_ios(device_ip: str) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_type="cisco_ios", device_ip=device_ip)


def cisco_ios_telnet(device_ip: str) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_type="cisco_ios_telnet", device_ip=device_ip)


def huawei_vrp(device_ip: str) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_type="huawei", device_ip=device_ip)


def get_config(device_type, net_device, commands: list or str) -> list or str:
    """
    Get configuration from network device
    -------------------------------------
    :param device_type: Callable function, generating dictionary with connection parameters
    :param net_device: SQLAlchemy ORM object
    :param commands: List of configuration commands or String one command
    :return:
    """
    logger.debug(f"Send {commands=} to {net_device.name}")
    try:
        if isinstance(commands, list):
            with ConnectHandler(**device_type(net_device.ip)) as ssh:
                ssh_out = []
                for cmd in commands:
                    logger.debug(f"Send command {cmd} to {net_device.name}")
                    out = ssh.send_command(cmd)
                    logger.debug(f"Out {out} from {cmd} in {net_device.name}")
                    ssh_out.append(out)
            return ssh_out
        else:
            with ConnectHandler(**cisco_ios(net_device.ip)) as ssh:
                ssh_out = ssh.send_command(commands)
                return ssh_out
    except (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
            ReadTimeout,
            AttributeError,
    ) as error:
        logger.error(error)
        return ['Error']


def send_config(device_type, net_device, commands: list) -> None:
    """
    Send configuration to network device
    :param net_device: SQLAlchemy ORM object
    :param commands: List of configuration commands
    :param device_type: Callable function, generating dictionary with connection parameters
    :return: None
    """
    logger.debug(f"Send {commands=} to {net_device.name}")
    try:
        with ConnectHandler(**device_type(net_device.ip)) as ssh:
            ssh.send_config_set(commands)
    except (
            NetmikoAuthenticationException,
            NetmikoTimeoutException,
            ReadTimeout,
            AttributeError,
    ) as err:
        logger.error(err)


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

