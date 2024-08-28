import asyncio
import logging
import subprocess
import threading


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
            args = ['su', '-c'] + args
        cmd += args

        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            stdout, stderr = p.communicate()

        if binary_output:
            result = stdout
        else:
            result = stdout.decode('utf-8')

        error_message = stderr.decode('utf-8')
        return p.returncode, result, error_message

        return result

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

# Usage
if __name__ == "__main__":
    adb = ADBCore()
    try:
        devices = adb.list_devices()
        print(devices)
    except Exception as e:
        print(e)
