import dataclasses

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .data_helper import ChatData, Screen, Battery, Network, DeviceProperties
import base64
import subprocess
import json
import time
import re


class ForensicCore:
    def __init__(self):
        """
            Initialize the object with a secret key.

            Parameters:
                self: The object itself.

            Returns:
                None
        """
        self.secret_key = 'very_secret_key'

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
        returncode, stdout, stderr = self.adb(['devices'])
        if returncode == 0:
            device_list = stdout.split('\n')[1:-2]  # Process the stdout to get the device list.
            for device in device_list:
                if device.strip():  # Making sure it's not an empty string.
                    device_info = device.split('\t')
                    if len(device_info) == 2:
                        device_id, device_state = device_info
                        encrypted_id_or_not = device_id
                        if self.isWiFi(device_id):
                            encrypted_id_or_not = self.encrypt(device_id, self.secret_key)

                        devices.append({
                            'id': encrypted_id_or_not,
                            'serial': self.decode_bytes_property(self.getProp(device_id, 'ro.serialno', 'unknown')),
                            'model': self.decode_bytes_property(self.getProp(device_id, 'ro.product.model', 'unknown')),
                            'isWiFi': self.isWiFi(device_id),
                        })
        else:
            print("Error: adb command failed with return code", returncode)
            print(stderr)  # Make sure to print or handle stderr

        return devices

    def get_list_of_devices(self):
        listDevices = []
        returncode, out, _ = self.adb(['devices'])

        # Check if the adb command was successful
        if returncode != 0:
            print("Error: adb command failed")
            return listDevices

        for line in out.split('\n'):
            tokens = line.split()
            if len(tokens) == 2 and tokens[1] == 'device':
                listDevices.append(tokens[0])

        return listDevices

    # ADB Core
    def adb(self, args, device=None, binary_output=False):
        adb_path = "/usr/bin/adb"
        adb_cmd = [adb_path]
        if device is not None:
            adb_cmd += ['-s', device]

        adb_cmd += args
        p = subprocess.Popen(adb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        if binary_output:
            return p.returncode, stdout, stderr.decode('utf-8') if stderr else ""
        else:
            try:
                stdout_str = stdout.decode('utf-8') if stdout else ""
            except UnicodeDecodeError:
                stdout_str = stdout.decode('latin-1') if stdout else ""

            try:
                stderr_str = stderr.decode('utf-8') if stderr else ""
            except UnicodeDecodeError:
                stderr_str = stderr.decode('latin-1') if stderr else ""

            return p.returncode, stdout_str, stderr_str

    # Get Screen
    def getScreen(self, device):
        (rc, out, err) = self.adb(['shell', 'dumpsys', 'display'], device=device)
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
                (rc, out, err) = self.adb(['shell', 'wm', 'density'], device=device)
                if rc == 0:
                    density_info = out.strip().split(':')
                    if len(density_info) == 2 and density_info[1].strip().isdigit():
                        screen['density'] = int(density_info[1].strip())

        except Exception as e:
            print("Failed to parse screen info:", e)
            return None

        print(f"Screen Info: {screen}")
        return screen

    # Get Battery
    def getBattery(self, device):
        (rc, out, err) = self.adb(['shell', 'dumpsys', 'battery'], device=device)
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
        (rc, out, err) = self.adb(["shell", "dumpsys wifi"], device=device)

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

        (rc, out, _) = self.adb(['shell', 'getprop', property], device=device)
        return out.strip() if rc == 0 and out.strip() else default

    def getCustomProp(self, device, property, default):
        (rc, out, _) = self.adb(['shell', property], device=device)
        return out.strip() if rc == 0 and out.strip() else default

    # Get Device
    def get_devices(self, request, id_or_not):
        if request.method == 'GET':

            start_time = time.time()
            devices = []
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

            devices.append(dataclasses.asdict(device_props))

            if len(devices) == 0:
                return JsonResponse({'message': 'No device connected'}, status=404)

            print("---Total Time: %s seconds ---" % (time.time() - start_time))

            return JsonResponse(devices, safe=False, status=200)

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

        (rc, out, err) = self.adb(["shell", f"su 0 -c dd if=/dev/block/{partition_id} | sha256sum"], device=device)

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

        (rc, out, err) = self.adb(["shell", "df /data/media | awk 'NR==2{print int($2/1024), int($3/1024)}'"],
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

        (rc, out, err) = self.adb(["shell", "su 0 -c ls /data/data"], device=device)
        if rc != 0:
            print(err)
            return []

        appList = [elem.replace('\r', '') for elem in out.split('\n')]

        return appList

    def getPartitionList(self, id):
        device = id

        if len(id) > 15 and self.checkSerialID(id):
            device = self.decrypt(id, self.secret_key)

        (rc, out, err) = self.adb(["shell", "su 0 -c cat /proc/partitions"], device=device)
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


forensic_core = ForensicCore()

def get_devices(request, id):
    return forensic_core.get_devices(request=request, id_or_not=id)


def getLogcat(request, id):
    if request.method == "GET":
        device = id
        if len(id) > 15 and forensic_core.checkSerialID(id):
            device = forensic_core.decrypt(id, forensic_core.secret_key)

        (rc, out, err) = forensic_core.adb(['logcat', '-d', '-v', 'brief'], device=device)
        if rc != 0:
            print(err)
            return HttpResponse(err)

        print("Ini isi out: ", type(out))
        return HttpResponse(out)


@csrf_exempt
def postKey(request, id):
    if request.method == 'POST':
        payload = json.loads(request.body.decode())  # Make sure to decode the request body from bytes to a string
        device = id
        if 'device' in payload and 'key' in payload:
            if len(id) > 15 and forensic_core.checkSerialID(id):
                device = forensic_core.decrypt(id, forensic_core.secret_key)

            key_event = str(payload['key'])  # Convert the key event code to a string
            print(f"{device} : {key_event}")
            (rc, _, err) = forensic_core.adb(['shell', 'input', 'keyevent', key_event], device=device)
            print(f'event done {rc}')
            if rc != 0:
                print(err)
                return JsonResponse({'error': err})

        return JsonResponse({'result': 'OK'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def postText(request, id):
    if request.method == 'POST':
        payload = json.loads(request.body.decode())  # Ensure decoding for compatibility
        device = id
        if 'device' in payload and 'text' in payload:
            if len(id) > 15 and forensic_core.checkSerialID(id):
                device = forensic_core.decrypt(id, forensic_core.secret_key)

            text = payload['text'].replace(' ', '%s')
            print("New:", device + ' : ' + str(text))
            (rc, _, err) = forensic_core.adb(['shell', 'input', 'text', '"' + text + '"'], device=device)
            print('event done ' + str(rc))
            if rc != 0:
                print(err)
                return JsonResponse({'error': err})

        return JsonResponse({'result': 'OK'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def postShell(request, id):
    if request.method == "POST":
        payload = json.loads(request.body.decode())  # Ensure decoding for compatibility
        device = id
        if 'device' in payload and 'command' in payload:
            if len(id) > 15 and forensic_core.checkSerialID(id):
                device = forensic_core.decrypt(id, forensic_core.secret_key)

            command = payload['command']
            print(device + ' : ' + command)

            (rc, out, err) = forensic_core.adb(['shell', command], device=device)
            print('shell done ' + str(rc))

            if rc != 0:
                print(err)
                return HttpResponse(err)

        return HttpResponse(out)


def getScreenshot(request, id):
    if request.method == "GET":
        device = id
        if len(id) > 15 and forensic_core.checkSerialID(id):
            device = forensic_core.decrypt(id, forensic_core.secret_key)

        (rc, out, err) = forensic_core.adb(['exec-out', 'screencap', '-p'], device=device, binary_output=True)
        if rc != 0:
            print(err)
            return HttpResponse(err, status=500)

        return HttpResponse(out, content_type="image/png")
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)
