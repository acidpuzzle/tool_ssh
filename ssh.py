# -*- coding: utf-8 -*-
import logging
import os

from netmiko import *
from ipaddress import ip_address
from concurrent.futures import ThreadPoolExecutor


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def netmiko_dev(device_ip: str,
                creds_env_var: str = None,
                *,
                device_type: str,
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
    :param creds_env_var:
    :return: Dictionary with device connection parameters
    """
    if creds_env_var:
        logger.debug(f"{creds_env_var=}")
        username, password, enable_pass = os.environ.get(creds_env_var).split(':')
    return {
        'device_type': device_type,
        'host': device_ip,
        'username': username,
        'password': password,
        'secret': enable_pass,
    }


def cisco_ios_ssh(device_ip: str, creds_env_var: str = None, **kwargs) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :param creds_env_var:
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_ip, creds_env_var=creds_env_var, device_type="cisco_ios", **kwargs)


def cisco_ios_telnet(device_ip: str, creds_env_var: str = None, **kwargs) -> dict:
    """
    :param device_ip: ip address in textual representation, for example "192.168.1.1"
    :param creds_env_var:
    :return: Dictionary with device connection parameters
    """
    return netmiko_dev(device_ip, creds_env_var=creds_env_var, device_type="cisco_ios_telnet", **kwargs)


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
        logger.error(err)


def get_config_ssh_or_telnet(device_ip: str, creds_env_var: str, command: str):
    """
    Send configuration to network device
    :param device_ip: SQLAlchemy ORM object
    :param creds_env_var:
    :param command: List of configuration commands
    :return:
    """
    logger.debug(f"Send {command=} to {device_ip=}")
    try:
        logger.debug(f"Trying SSH to {device_ip=}")
        return get_config(cisco_ios_ssh(device_ip, creds_env_var=creds_env_var), command)
    except NetmikoTimeoutException:
        logger.debug(f"Trying Telnet to {device_ip=}")
        return get_config(cisco_ios_telnet(device_ip, creds_env_var=creds_env_var), command)
    except (
            NetmikoAuthenticationException,
            ReadTimeout,
            AttributeError,
            WindowsError,
            ValueError,
    ) as err:
        logger.error(err)
        return err.__str__


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
        logger.error(err)


def run_in_threads(worker, *args, max_thread=50):
    """
    len(all_devices) == len(all_commands) = True
    :param worker: a function that will run in threads
    :param max_thread: Maximum number of threads
    :return:
    """
    with ThreadPoolExecutor(max_workers=max_thread) as executor:
        results = executor.map(worker, *args)

    return results

