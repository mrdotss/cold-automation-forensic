import asyncio
import logging
import subprocess
import threading
import socket
import random


class ADBCore:
    """
    ADBCore class for enhanced Android Debug Bridge (ADB) communication, combining
    simple functionality with advanced features like logging and structured command execution.
    """
    _instance = None
    _lock = threading.Lock()  # Ensures thread-safe singleton instantiation

    def __new__(cls, adb_path='/usr/bin/adb', logger=None):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(ADBCore, cls).__new__(cls)
                # Initialize any variables here, if necessary
                cls._instance.setup(adb_path, logger)
            return cls._instance

    def setup(self, adb_path, logger):
        self.adb_path = adb_path
        self.logger = logger or self.setup_logging()

    def setup_logging(self):
        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger

    def adb(self, args, device=None, binary_output=False, use_su=False):
        cmd = [self.adb_path]
        if device:
            cmd += ['-s', device]
        if use_su:
            args = ['su 0 -c'] + args
        cmd += args

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            stdout, stderr = p.communicate()

        if binary_output:
            result = stdout
        else:
            result = stdout.decode('utf-8')

        error_message = stderr.decode('utf-8')
        return p.returncode, result, error_message

    def adb_forward_generator(self, device=None, local_port=None, remote_port=None):
        """
        Generates an adb forward to an available local port.

        Parameters:
            device (str): The serial number of the device. If None, uses default device.
            local_port (int): The local host port to use. If None, finds an available port.
            remote_port (int): The remote device port to forward to. Default is 5555.

        Returns:
            int: The local port number used for forwarding, or None if failed.
        """
        # First, get the list of current forwards
        rc, out, err = self.adb(['forward', '--list'], device=device)
        if rc != 0:
            self.logger.error(f"Failed to get adb forward list: {err}")
            return None

        used_ports = set()
        for line in out.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 3:
                # Format: <serial> <local> <remote>
                local = parts[1]
                if local.startswith('tcp:'):
                    port = int(local[4:])
                    used_ports.add(port)

        # If local_port is specified, check if it's available
        if local_port:
            if local_port in used_ports or not self.is_port_available(local_port):
                self.logger.error(f"Specified local port {local_port} is not available")
                return None
        else:
            # Find an available port
            for _ in range(1000):  # Try up to 1000 times
                port = random.randint(50000, 60000)
                if port not in used_ports and self.is_port_available(port):
                    local_port = port
                    break
            else:
                self.logger.error("Failed to find an available port")
                return None

        # Set default remote_port if not specified
        if remote_port is None:
            remote_port = 5555  # Default remote port

        # Now, set up the forward
        rc, out, err = self.adb(['forward', f'tcp:{local_port}', f'tcp:{remote_port}'], device=device)
        if rc != 0:
            self.logger.error(f"Failed to set adb forward: {err}")
            return None

        self.logger.info(f"Set up adb forward tcp:{local_port} -> tcp:{remote_port} on device {device}")
        return local_port

    def is_port_available(self, port):
        """
        Checks if a port is available on the host.

        Parameters:
            port (int): The port number to check.

        Returns:
            bool: True if the port is available, False otherwise.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('', port))
                return True
            except OSError:
                return False

    def adb_forward_list(self, device=None):
        """
        Returns a list of current adb forwards.

        Parameters:
            device (str): The serial number of the device. If None, uses default device.

        Returns:
            list: A list of tuples (serial, local, remote).
        """
        rc, out, err = self.adb(['forward', '--list'], device=device)
        if rc != 0:
            self.logger.error(f"Failed to get adb forward list: {err}")
            return []

        forwards = []
        for line in out.strip().split('\n'):
            parts = line.strip().split()
            if len(parts) >= 3:
                serial = parts[0]
                local = parts[1]
                remote = parts[2]
                forwards.append((serial, local, remote))
        return forwards

    def adb_forward_remove(self, local_port, device=None):
        """
        Removes an adb forward.

        Parameters:
            local_port (int): The local port number of the forward to remove.
            device (str): The serial number of the device. If None, uses default device.

        Returns:
            bool: True if successful, False otherwise.
        """
        rc, out, err = self.adb(['forward', '--remove', f'tcp:{local_port}'], device=device)
        if rc != 0:
            self.logger.error(f"Failed to remove adb forward tcp:{local_port}: {err}")
            return False
        self.logger.info(f"Removed adb forward tcp:{local_port}")
        return True

    def adb_forward_remove_all(self, device=None):
        """
        Removes all adb forwards.

        Parameters:
            device (str): The serial number of the device. If None, uses default device.

        Returns:
            bool: True if successful, False otherwise.
        """
        rc, out, err = self.adb(['forward', '--remove-all'], device=device)
        if rc != 0:
            self.logger.error(f"Failed to remove all adb forwards: {err}")
            return False
        self.logger.info("Removed all adb forwards")
        return True

    def pull_file(self, remote_path, local_path):
        self.logger.info(f'Pulling file from {remote_path} to {local_path}')
        return self.adb(['pull', remote_path, local_path])

    def push_file(self, local_path, remote_path):
        self.logger.info(f'Pushing file from {local_path} to {remote_path}')
        return self.adb(['push', local_path, remote_path])

    def reboot_device(self, mode=None):
        if mode:
            self.logger.info(f'Rebooting device to {mode} mode')
            return self.adb(['reboot', mode])
        else:
            self.logger.info('Rebooting device')
            return self.adb(['reboot'])

    def list_devices(self):
        self.logger.info('Listing connected devices')
        return self.adb(['devices'])

    def install_app(self, apk_path):
        self.logger.info(f'Installing APK from {apk_path}')
        return self.adb(['install', apk_path])
