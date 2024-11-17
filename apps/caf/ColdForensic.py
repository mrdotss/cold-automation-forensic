from django.http import JsonResponse
from .data_helper import ChatData, Screen, Battery, Network, DeviceProperties
from .ADBCore import ADBCore
import dataclasses
import base64
import time
import re, os
import logging
from apps.home.models import Acquisition

class ColdForensic:
    def __init__(self):
        """
            Initialize the object with a secret key.

            Parameters:
                self: The object itself.

            Returns:
                None
        """
        self.secret_key = 'very_secret_key'
        self.adb_instance = ADBCore()
        self.original_busybox = f'{os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}/resources/busybox'
        self.remote_busybox_sdcard = '/sdcard/busybox'
        self.remote_busybox_destination = '/data/local/busybox'

    def setup_logging(self):
        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger

    def is_hashed_ip_or_not(self, id):
        return len(id) > 15

    def isRooted(self, id):
        device = id

        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(
            ["shell", 'su -c "id" >/dev/null 2>&1 && echo "root" || echo "unroot"'],
            device=device
        )

        if rc != 0:
            print(err)
            return []

        return out.strip() == "root"

    def isWiFi(self, id):
        """
        Check if the given ID is a valid WiFi address.

        :param id: The ID to check if it is a valid WiFi address.
        :type id: str
        :return: True if the ID is a valid WiFi address, False otherwise.
        :rtype: bool
        """
        pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$'
        return bool(re.match(pattern, id))

    def check_if_hashed_ip(self, encoded, key):
        """Attempts to decrypt the encoded data and checks if it is a valid IP address."""
        decrypted_data = self.decrypt(encoded, key)
        if self.isWiFi(decrypted_data):
            return True, decrypted_data  # It's a hashed IP address
        else:
            return False, None  # Not a hashed IP address

    def xor_cipher(self, data, key):
        """
        Applies XOR cipher to the given data using the provided key.

        :param data: The string to be encrypted.
        :param key: The key used for encryption.
        :return: The encrypted string.
        """
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

    def encrypt(self, data, key):
        """Encrypts the data using the XOR cipher with the provided key.

        Parameters:
            data (str): The data to be encrypted.
            key (str): The key to be used for encryption.

        Returns:
            str: The encrypted data.

        Example:
            >>> obj = Encryptor()
            >>> data = "Hello, world!"
            >>> key = "secret"
            >>> encrypted_data = obj.encrypt(data, key)
            >>> print(encrypted_data)
            'ewgjKisSQA=='

        Note:
            The method uses the XOR cipher to encrypt the data by performing bitwise XOR operation between
            each character of the data and the corresponding character of the key. The encrypted data is then
            base64 encoded using URL-safe characters and the padding characters (=) at the end are removed."""
        encrypted = self.xor_cipher(data, key)
        return base64.urlsafe_b64encode(encrypted.encode()).decode().rstrip("=")

    def decrypt(self, encoded, key):
        """
        Decrypts an encoded string using a specified key.

        Parameters:
        - encoded (str): The encoded string that needs to be decrypted.
        - key (str): The key used for decryption.

        Returns:
        - str: The decrypted string.
        """
        encrypted = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        return self.xor_cipher(encrypted.decode(), key)

    def decode_bytes_property(self, value):
        """
        Decode bytes property to string if it is an instance of bytes.

        Parameters:
            value (bytes): The bytes property to be decoded.

        Returns:
            str: The decoded string value if `value` is an instance of bytes, or `value` itself if it is not.
        """
        if isinstance(value, bytes):
            return value.decode('utf-8')
        return value

    def get_select_device(self):
        """
        Method: get_select_device
        Parameters:
        - self : Object reference to the current instance of the class

        Description:
        This method retrieves the list of connected devices using the 'adb devices' command and returns a list of dictionaries containing information about each device.

        Returns:
        - devices : A list of dictionaries containing the following device information:
            - 'id' : The encrypted or original device ID
            - 'serial' : The decoded serial number of the device
            - 'model' : The decoded model name of the device
            - 'isWiFi' : Boolean indicating whether the device is connected via Wi-Fi or not

        Example:

            devices = get_select_device()

            Output:
            [{'id': 'encrypted_id_or_not', 'serial': 'decoded_serial_number', 'model': 'decoded_model_name', 'isWiFi': True}, ...]
        """
        devices = []
        try:
            returncode, stdout, stderr = self.adb_instance.adb(['devices'])
            if returncode != 0:
                print(f"Error executing adb command: {stderr}")
                return devices
            device_list = stdout.split('\n')[1:-2]
        except Exception as e:
            print(f"Error executing adb command: {str(e)}")
            return devices

        for device in device_list:
            if device.strip():
                device_info = device.split('\t')
                if len(device_info) == 2:
                    device_id, device_state = device_info
                    encrypted_id_or_not = device_id
                    if self.isWiFi(device_id):  # Assuming isWiFi is defined somewhere in ColdForensic
                        encrypted_id_or_not = self.encrypt(device_id, self.secret_key)  # Assuming encrypt is defined

                    devices.append({
                        'id': encrypted_id_or_not,
                        'serial': self.decode_bytes_property(self.getProp(device_id, 'ro.serialno', 'unknown')),
                        # Assuming getProp and decode_bytes_property are defined
                        'model': self.decode_bytes_property(self.getProp(device_id, 'ro.product.model', 'unknown')),
                        'isWiFi': self.isWiFi(device_id),
                    })

        return devices

    def get_list_of_devices(self):
        listDevices = []
        returncode, out, _ = self.adb_instance.adb(['devices'])

        # Check if the adb command was successful
        if returncode != 0:
            print("Error: adb command failed")
            return listDevices

        for line in out.split('\n'):
            tokens = line.split()
            if len(tokens) == 2 and tokens[1] == 'device':
                listDevices.append(tokens[0])

        return listDevices

    # Get Screen
    def getScreen(self, device):
        (rc, out, err) = self.adb_instance.adb(['shell', 'dumpsys', 'display'], device=device)
        if rc != 0:
            print("Error executing ADB command:", err)
            return None

        screen = {
            'width': 0,
            'height': 0,
            'orientation': 0,
            'density': 0
        }

        try:
            # Process display information
            for line in out.split('\n'):
                # Extract width and height from DisplayInfo
                if 'DisplayInfo' in line and 'real' in line:
                    match = re.search(r'real (\d+) x (\d+)', line)
                    if match:
                        screen['width'] = int(match.group(1))
                        screen['height'] = int(match.group(2))

                # Extract orientation
                if 'mCurrentOrientation' in line:
                    match = re.search(r'mCurrentOrientation=(\d+)', line)
                    if match:
                        screen['orientation'] = int(match.group(1))

                # Extract density
                if 'density' in line and 'dpi' in line:
                    match = re.search(r'density=(\d+)', line)
                    if match:
                        screen['density'] = int(match.group(1))

            # If density is not found in dumpsys display, use wm density
            if screen['density'] == 0:
                (rc, out, err) = self.adb_instance.adb(['shell', 'wm', 'density'], device=device)
                if rc == 0:
                    density_info = out.strip().split(':')
                    if len(density_info) == 2 and density_info[1].strip().isdigit():
                        screen['density'] = int(density_info[1].strip())

            print(f"Screen Info: {screen}")
            return screen

        except Exception as e:
            print("Failed to parse screen info:", e)
            return None

    # Get Battery
    def getBattery(self, device):
        (rc, out, err) = self.adb_instance.adb(['shell', 'dumpsys', 'battery'], device=device)
        print(f'battery done {rc}')

        if rc != 0:
            print(err)
            return None  # Ensure to handle error cases appropriately

        battery = {
            'plugged': 0,
            'level': 0,
            'status': 1,
            'health': 1
        }

        for line in out.split('\n'):
            tokens = line.split(': ')
            if len(tokens) < 2:
                continue

            key = tokens[0].strip().lower()
            value = tokens[1].strip().lower()
            if key == "ac powered" and value == "true":
                battery['plugged'] = 'AC'
            elif key == 'usb powered' and value == 'true':
                battery['plugged'] = 'USB'
            elif key == 'wireless powered' and value == 'true':
                battery['plugged'] = 'Wireless'
            elif key == 'level':
                battery['level'] = int(value)
            elif key == 'status':
                battery['status'] = int(value)
            elif key == 'health':
                battery['health'] = value

        battery = Battery(
            plugged=battery['plugged'],
            level=battery['level'],
            status=battery['status'],
            health=str(battery['health'])
        )

        return battery

    # Get Network
    def getNetwork(self, device):
        # Execute the adb command to get the wifi status
        (rc, out, err) = self.adb_instance.adb(["shell", "dumpsys wifi"], device=device)

        # Check if the command executed successfully
        if rc != 0:
            print("Error:", err)
            return None  # or handle the error accordingly

        # Initialize the network dictionary
        network = {
            'connected': False,
            'ssid': ''
        }

        # Try to find 'current SSID' pattern
        match = re.search(r'current SSID\(\w+\):{iface=\w+,ssid="([^"]+)"}', out)
        if match:
            network['connected'] = True
            network['ssid'] = match.group(1)
        else:
            # Try to find SSID in the format used by Samsung Note 3
            match = re.search(r'SSID="([^"]+)"', out)
            if match:
                network['connected'] = True
                network['ssid'] = match.group(1)

        # Print the extracted network information
        print("Network Info:", network)

        # Assuming Network is a class you defined somewhere
        return Network(
            connected=network['connected'],
            ssid=network['ssid']
        )

    # Get Prob Device
    def getProp(self, device, property, default):
        try:
            rc, out, err = self.adb_instance.adb(['shell', 'getprop', property], device=device)
            return out.strip() if rc == 0 and out.strip() else default
        except Exception as e:
            print(f"Unexpected error retrieving property {property}: {str(e)}")
            return default

    def getCustomProp(self, device, property, default):
        (rc, out, _) = self.adb_instance.adb(['shell', property], device=device)
        return out.strip() if rc == 0 and out.strip() else default

    # Get Device
    def get_devices(self, request, id_or_not):
        if request.method == 'GET':

            start_time = time.time()
            listDevices = self.get_list_of_devices()
            id = None
            for device in listDevices:
                if id_or_not == device:
                    id = device
                    break

            if not self.checkSerialID(id_or_not):
                print("Device not found")
                return JsonResponse({'message': "404 Not Found"}, status=404)

            encrypted_id_or_not = None

            # Commonly, serial number len is 10-15, so I assume if the id_or_not > 15, it is hashed ip address
            if len(id_or_not) > 15:
                id = self.decrypt(id_or_not, self.secret_key)
                if self.isWiFi(id):
                    encrypted_id_or_not = self.encrypt(id, self.secret_key)
            else:
                encrypted_id_or_not = id_or_not

            device_props = DeviceProperties(
                id=encrypted_id_or_not,
                serial=self.decode_bytes_property(self.getProp(id, 'ro.serialno', 'unknown')),
                isWiFi=self.isWiFi(id),
                isRooted=self.isRooted(id),
                manufacturer=self.decode_bytes_property(self.getProp(id, 'ro.product.manufacturer', 'unknown')),
                model=self.decode_bytes_property(self.getProp(id, 'ro.product.model', 'unknown')),
                sdk=self.decode_bytes_property(self.getProp(id, 'ro.build.version.sdk', 'unknown')),
                timezone=self.decode_bytes_property(self.getProp(id, 'persist.sys.timezone', 'unknown')),
                product=self.decode_bytes_property(self.getProp(id, 'ro.build.product', 'unknown')),
                security_patch=self.decode_bytes_property(
                    self.getProp(id, 'ro.build.version.security_patch', 'unknown')),
                api_level=self.decode_bytes_property(self.getProp(id, 'ro.product.first_api_level', 'unknown')),
                SELinux=self.decode_bytes_property(self.getCustomProp(id, 'getenforce', 'unknown')),
                AndroidID=self.decode_bytes_property(
                    self.getCustomProp(id, 'settings get secure android_id', 'unknown')),
                operator=self.decode_bytes_property(self.getProp(id, 'gsm.sim.operator.alpha', 'unknown')),
                IMEI=self.decode_bytes_property(self.getCustomProp(id,
                                                                   "service call iphonesubinfo 1 s16 com.android.shell | cut -c 52-66 | tr -d '.[:space:]'",
                                                                   'unknown')),
                network=self.getNetwork(id),
                battery=self.getBattery(id),
                screen=self.getScreen(id),
                IP='NULL',
            )

            if self.isWiFi(id):
                device_props.IP = id.split(':')[0]

            print("---Total Time: %s seconds ---" % (time.time() - start_time))

            # Return device_props as object without json
            return device_props


    def checkSerialID(self, serial_id):
        listDevices = self.get_list_of_devices()

        for device in listDevices:
            if self.isWiFi(device):
                if serial_id == self.encrypt(device, self.secret_key):
                    return True
            else:
                if serial_id == device:
                    return True

    def hashPartition(self, serial_id, partition_id):
        device = serial_id
        if len(serial_id) > 15 and self.checkSerialID(serial_id):
            device = self.decrypt(serial_id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(["shell", f"su 0 -c dd if=/dev/block/{partition_id} | sha256sum"], device=device)

        if rc != 0:
            print(err)
            return None  # Handle errors appropriately

        hash_output = out.strip().split()[0]
        print("Hash:", hash_output)

        return hash_output

    def getStorage(self, id):
        device = id
        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(["shell", "df /data/media | awk 'NR==2{print int($2/1024), int($3/1024)}'"],
                                  device=device)
        if rc != 0:
            print(err)
            return None  # Handle errors appropriately

        numbers = [int(num) for num in re.findall(r'\d+', out)]

        print("Ini isi numbers: ", numbers)

        if len(numbers) >= 2:
            storage = {
                'total': numbers[0],  # Total storage in MB
                'used': numbers[1]  # Used storage in MB
            }
        else:
            storage = None  # In case parsing fails

        print("Ini isi storage: ", storage)

        return storage

    def getAppList(self, id):
        device = id
        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(["shell", "su 0 -c ls /data/data"], device=device)
        if rc != 0:
            print(err)
            return []

        appList = [elem.replace('\r', '') for elem in out.split('\n')]

        return appList

    def getPartitionList(self, id):
        device = id

        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(["shell", "su 0 -c cat /proc/partitions"], device=device)
        if rc != 0:
            print(err)
            return []

        # Remove the first line
        lines = out.strip().split('\n')[2:]

        # Now we can create a list of dictionaries, each representing a partition
        partitions = []
        for line in lines:
            parts = line.split()
            if len(parts) < 4:  # Ensure we have all the needed parts
                continue

            partitions.append({
                "major": int(parts[0]),
                "minor": int(parts[1]),
                "blocks": int(parts[2]),
                "name": parts[3]
            })

        return partitions

    def getFullFileSystem(self,id):
        device = id

        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(["shell", "su 0 -c ls /data/data"], device=device)

        if rc != 0:
            print(err)
            return []

        # Add file system directory to the list
        fileSystemList = []

        for out in out.split('\n'):
            fileSystemList.append(out)

        return fileSystemList

    def setupBusybox(self, id):
        device = id

        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb_instance.adb(['shell', 'ls', self.remote_busybox_destination], device=device)

        if rc == 0 and 'No such file or directory' not in err:
            busybox_exists = True
        else:
            busybox_exists = False

        # If busybox does not exist, perform the setup
        if not busybox_exists:
            # Step 2: Push busybox to /sdcard/busybox
            (rc, out, err) = self.adb_instance.adb(['push', self.original_busybox, self.remote_busybox_sdcard],
                                               device=device)
            if rc != 0:
                print(err)
                return []

            # Step 3: Move busybox to /data/local/busybox
            (rc, out, err) = self.adb_instance.adb(
                ['shell', 'su 0 -c', f'mv {self.remote_busybox_sdcard} {self.remote_busybox_destination}'],
                device=device)
            if rc != 0:
                print(err)
                return []

            # Step 4: Set permissions
            (rc, out, err) = self.adb_instance.adb(['shell', 'su 0 -c', f'chmod 755 {self.remote_busybox_destination}'],
                                             device=device)
            if rc != 0:
                print(err)
                return []

            # Step 5: Verify busybox is executable
            (rc, out, err) = self.adb_instance.adb(['shell', 'su 0 -c', self.remote_busybox_destination, '--help'],
                                             device=device)
            if rc != 0:
                print(err)
                return []

        return True