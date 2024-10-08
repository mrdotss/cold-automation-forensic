import datetime
import hashlib
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from django.test import RequestFactory

from asgiref.sync import async_to_sync
from celery import shared_task
from channels.layers import get_channel_layer
from django.core.exceptions import ObjectDoesNotExist

from apps.caf.cold_action import adb_instance
from apps.home.models import Acquisition, PhysicalAcquisition
from core.celery import app
from apps.caf.ColdForensic import ColdForensic

__all__ = ('app',)
logger = logging.getLogger(__name__)
logging.basicConfig(filename="acquisition.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@shared_task
def physicalAcquisition(group_name, unique_code):
    channel_layer = get_channel_layer()
    getAcquisitionObject = Acquisition.objects.get(unique_link=unique_code)
    forensic_core = ColdForensic()
    request_factory = RequestFactory()

    IP = getAcquisitionObject.client_ip
    PORT_CLIENT = getAcquisitionObject.port
    LOCATION = getAcquisitionObject.full_path
    FILE_NAME = getAcquisitionObject.file_name
    PARTITION = getAcquisitionObject.physical.partition_id
    BRIDGE = getAcquisitionObject.connection_type

    is_usb_connection = BRIDGE.lower() == 'usb'

    SERIAL_ID = getAcquisitionObject.device_id if not forensic_core.is_hashed_ip_or_not(getAcquisitionObject.device_id) else forensic_core.decrypt(getAcquisitionObject.device_id, forensic_core.secret_key)

    # Set up busybox on the device
    busybox_installed = forensic_core.setupBusybox(getAcquisitionObject.device_id)
    if not busybox_installed:
        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                'type': 'acquisition_error',
                'message': 'Failed to set up busybox on the device.',
            }
        )
        return

    PORT_SERVER = 5555  # Fixed port on the device

    acquisition_start_time = datetime.now()

    # Check if need to hash before acquisition
    if hasattr(getAcquisitionObject, 'physical'):

        # Set up adb port forwarding if USB connection
        if is_usb_connection and (getAcquisitionObject.physical.total_transferred_bytes == 0 or getAcquisitionObject.physical.total_transferred_bytes  > 0):
            # Forward the device's listening port to a local port
            local_port = adb_instance.adb_forward_generator(device=SERIAL_ID, remote_port=PORT_SERVER)
            if local_port is None:
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'acquisition_error',
                        'message': 'Failed to set up adb port forwarding.',
                    }
                )
                return
            # Update IP and PORT_CLIENT to use localhost and the forwarded port
            IP = '127.0.0.1'
            PORT_CLIENT = local_port
        else:
            # For TCP/IP connections, ensure PORT_CLIENT is set to the correct device port
            PORT_CLIENT = PORT_SERVER  # Assuming PORT_SERVER is the port on the device

        if getAcquisitionObject.physical.is_verify_first:
            try:
                # Start time for the acquisition
                acquisition_start_time = datetime.now()
                getAcquisitionObject.physical.start_time = acquisition_start_time
                getAcquisitionObject.physical.save()

                time.sleep(5)
                # Send a message to the client
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'update_progress',
                        'message': 'Please wait, hashing the partition from the device before acquisition...',
                    }
                )

                hashOutput = forensic_core.hashPartition(serial_id=SERIAL_ID, partition_id=PARTITION) if not getAcquisitionObject.physical.hash_before_acquisition else getAcquisitionObject.physical.hash_before_acquisition
                getAcquisitionObject.physical.hash_before_acquisition = hashOutput
                getAcquisitionObject.physical.save()

                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'update_progress',
                        'message': 'Hashing done, now starting acquisition...',
                    }
                )
            except Exception as e:
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'acquisition_error',
                        'message': f'Hashing failed: {str(e)}',
                    }
                )
                return

        time.sleep(2)

    try:
        # Check if we need to resume
        seek_skip_block = getAcquisitionObject.physical.total_transferred_bytes or 0

        # Determine which 'dd' and 'nc' commands to use on the device
        dd_command = '/data/local/busybox dd'
        nc_command = '/data/local/busybox nc'

        # Set block size
        bs = 512
        seek_blocks = seek_skip_block // bs

        # Construct the android_command without iflag=fullblock and -w option
        android_command = f"adb -s {SERIAL_ID} shell \"su 0 -c '{dd_command} if=/dev/block/{PARTITION} bs={bs}"
        if seek_skip_block > 0:
            android_command += f" skip={seek_blocks}"
        android_command += f" | {nc_command} -l -p {PORT_SERVER}'\""

        # Start the android_process first
        android_process = subprocess.Popen(android_command, shell=True)
        time.sleep(2)

        # Construct the server_command with -q option (if supported)
        if seek_skip_block > 0:
            server_command = f"netcat {IP} {PORT_CLIENT} -q 1 | dd of={LOCATION}/{FILE_NAME} bs={bs} seek={seek_blocks} conv=fsync"
        else:
            server_command = f"netcat {IP} {PORT_CLIENT} -q 1 | dd of={LOCATION}/{FILE_NAME} bs={bs} conv=fsync"

        # Start the server_process after the device is listening
        server_process = subprocess.Popen(server_command, shell=True)
        time.sleep(2)

        total_size_kb = int(getAcquisitionObject.physical.partition_size)
        total_size_bytes = total_size_kb*1024
        progress = (seek_skip_block / total_size_bytes) * 100 if seek_skip_block > 0 else 0
        last_file_size = seek_skip_block

        start_time = time.time()
        last_time = start_time

        N = 4
        MIN_TRANSFER_RATE = 1e5
        recent_transfer_rates = [MIN_TRANSFER_RATE] * N

        last_size = last_file_size
        timeout_counter = 0
        TIMEOUT_THRESHOLD = 15

        new_progress = progress
        estimated_time_remaining = 0

        logging.basicConfig(filename="file.log", level=logging.INFO, format='%(asctime=s - %(message=s')

        while True:
            current_time = time.time()
            elapsed_time = current_time - start_time
            time_since_last_check = current_time - last_time

            file_size = os.path.getsize(f'{LOCATION}/{FILE_NAME}')
            data_transferred_since_last_check = file_size - last_file_size
            current_transfer_rate = data_transferred_since_last_check / time_since_last_check if time_since_last_check else 0

            recent_transfer_rates.append(current_transfer_rate)
            if len(recent_transfer_rates) > N:
                recent_transfer_rates.pop(0)

            avg_transfer_rate = sum(recent_transfer_rates) / len(recent_transfer_rates) if recent_transfer_rates else 0
            remaining_data = max(0, total_size_bytes - file_size)
            print(f"Remaining data: {remaining_data} bytes")

            if avg_transfer_rate > 0:
                estimated_time_remaining = remaining_data / avg_transfer_rate
                estimated_time_string = f"{round(estimated_time_remaining, 2)} seconds"
            else:
                estimated_time_string = "calculating..."

            estimated_time_remaining = max(estimated_time_remaining, 0)

            last_file_size = file_size
            last_time = current_time

            new_progress = (file_size / total_size_bytes) * 100

            if new_progress != progress:
                progress = new_progress
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'update_progress',
                        'progress': progress,
                        'message': 'Acquisition in progress...',
                        'estimated_time_remaining': round(estimated_time_remaining, 2),
                    }
                )
            else:
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'update_progress',
                        'progress': progress,
                        'estimated_time_remaining': round(estimated_time_remaining, 2),
                        'message': 'Please wait while just checking up...',
                    }
                )

            time.sleep(2)

            current_size = os.path.getsize(f'{LOCATION}/{FILE_NAME}')
            if current_size == last_size:
                timeout_counter += 1
                getAcquisitionObject.physical.total_transferred_bytes = current_size
                getAcquisitionObject.physical.save()

                if timeout_counter >= TIMEOUT_THRESHOLD and getAcquisitionObject.physical.total_transferred_bytes == total_size_bytes:
                    terminate_process(server_process)
                    terminate_process(android_process)

                    # Wait for the termination process
                    time.sleep(5)

                    release_file_handles(f'{LOCATION}/{FILE_NAME}')
                    file_path = os.path.join(LOCATION, FILE_NAME)

                    # Send a message to the client
                    async_to_sync(channel_layer.group_send)(
                        group_name,
                        {
                            'type': 'update_progress',
                            'progress': progress,
                            'message': 'Acquisition complete, now calculating the hash...',
                        }
                    )

                    file_hashed = compute_sha256_hash(file_path)
                    acquisition_end_time = datetime.now()
                    acquisition_duration = acquisition_end_time - acquisition_start_time

                    # Send a message to the client
                    async_to_sync(channel_layer.group_send)(
                        group_name,
                        {
                            'type': 'update_progress',
                            'progress': progress,
                            'message': 'Hashing complete, now generate report...',
                        }
                    )

                    # Create a mock request for internal call
                    mock_request = request_factory.get(f'/get_devices/{getAcquisitionObject.device_id}')
                    device_info_response = forensic_core.get_devices(mock_request, getAcquisitionObject.device_id)
                    device_info = json.loads(device_info_response.content)[0]

                    # Format the device info properly
                    evidence_info = f"""
Evidence Information:
- ID: {device_info.get('id')}
- Serial: {device_info.get('serial')}
- WiFi: {device_info.get('isWiFi')}
- Manufacturer: {device_info.get('manufacturer')}
- Model: {device_info.get('model')}
- SDK: {device_info.get('sdk')}
- IP: {device_info.get('IP')}
- Timezone: {device_info.get('timezone')}
- Product: {device_info.get('product')}
- Security Patch: {device_info.get('security_patch')}
- API Level: {device_info.get('api_level')}
- SELinux: {device_info.get('SELinux')}
- Android ID: {device_info.get('AndroidID')}
- Operator: {device_info.get('operator')}
- IMEI: {device_info.get('IMEI')}
- Network:
  - SSID: {device_info['network'].get('ssid')}
  - Connected: {device_info['network'].get('connected')}
- Battery:
  - Level: {device_info['battery'].get('level')}
  - Status: {device_info['battery'].get('status')}
  - Plugged: {device_info['battery'].get('plugged')}
- Screen:
  - Resolution: {device_info['screen'].get('resolution')}
  - Density: {device_info['screen'].get('density')}"""

                    report_content = f"""Acquisition Report
==================
{evidence_info}

Acquisition Details:
- Acquisition Start Time: {acquisition_start_time.strftime('%Y-%m-%d %H:%M:%S')}
- Acquisition End Time: {acquisition_end_time.strftime('%Y-%m-%d %H:%M:%S')}
- Total Duration: {acquisition_duration}
- Size: {total_size_kb} KB
- Location Folder: {LOCATION}
- File Name: {FILE_NAME}
- Client IP: {IP}
- Partition: {PARTITION}

Verification:
- Hash Verification: {getAcquisitionObject.physical.is_verify_first}
- Original Hash: {getAcquisitionObject.physical.hash_before_acquisition}
- Resulting Hash: {file_hashed}"""

                    with open(f"{LOCATION}/acquisition_report_{FILE_NAME}.txt", 'w') as report_file:
                        report_file.write(report_content)

                    getAcquisitionObject.physical.hash_after_acquisition = file_hashed
                    getAcquisitionObject.physical.total_transferred_bytes = current_size
                    getAcquisitionObject.physical.end_time = acquisition_end_time
                    getAcquisitionObject.physical.save()

                    getAcquisitionObject.status = 'completed'
                    getAcquisitionObject.last_active = datetime.now()
                    getAcquisitionObject.save()

                    # Clean up adb forwarding if USB connection
                    if is_usb_connection:
                        adb_instance.adb_forward_remove(local_port, device=SERIAL_ID)

                    async_to_sync(channel_layer.group_send)(
                        group_name,
                        {
                            'type': 'acquisition_completed',
                            'message': 'Acquisition Completed',
                            'report_location': f"{LOCATION}/acquisition_report_{FILE_NAME}.txt"
                        }
                    )
                    break

                if timeout_counter >= TIMEOUT_THRESHOLD and all(rate == 0 for rate in recent_transfer_rates) and remaining_data > 0:
                    getAcquisitionObject.status = 'failed'
                    getAcquisitionObject.last_active = datetime.now()
                    getAcquisitionObject.save()
                    terminate_process(server_process)
                    terminate_process(android_process)

                    # Clean up adb forwarding if USB connection
                    if is_usb_connection:
                        adb_instance.adb_forward_remove(local_port, device=SERIAL_ID)

                    async_to_sync(channel_layer.group_send)(
                        group_name,
                        {
                            'type': 'acquisition_error',
                            'message': 'Acquisition failed due to timeout',
                        }
                    )
                    break
            else:
                timeout_counter = 0
            last_size = current_size

    except Exception as e:
        logging.error(f"Error during acquisition: {e}")

        # Clean up adb forwarding if USB connection
        if is_usb_connection:
            adb_instance.adb_forward_remove(local_port, device=SERIAL_ID)

        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                'type': 'acquisition_error',
                'message': f"Error: {str(e)}",
            }
        )

    except KeyboardInterrupt:
        terminate_process(server_process)
        terminate_process(android_process)
        release_file_handles(f'{LOCATION}/{FILE_NAME}')

        # Clean up adb forwarding if USB connection
        if is_usb_connection:
            adb_instance.adb_forward_remove(local_port, device=SERIAL_ID)

        async_to_sync(channel_layer.group_send)(
            group_name,
            {
                'type': 'acquisition_error',
                'message': 'Acquisition interrupted by user.',
            }
        )
        return


def terminate_process(process):
    """Terminate a process and its child processes."""
    import psutil

    def terminate(proc):
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass

    def kill(proc):
        try:
            proc.kill()
        except psutil.NoSuchProcess:
            pass

    if process and process.poll() is None:
        ps_process = psutil.Process(process.pid)
        children = ps_process.children(recursive=True)
        for child in children:
            terminate(child)
        terminate(ps_process)

        try:
            ps_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            for child in children:
                kill(child)
            kill(ps_process)

def release_file_handles(file_path):
    """Ensure all file handles are released."""
    with open(file_path, 'rb') as file:
        file.close()
    if hasattr(os, 'sync'):
        os.sync()
    if hasattr(os, 'system'):
        os.system(f'lsof | grep {file_path}')
    # Use psutil to close processes holding the file
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):
            for file in proc.info['open_files'] or []:
                if file.path == file_path:
                    proc.terminate()
                    proc.wait()
    except ImportError:
        pass

@shared_task
def compute_sha256_hash(file_path):
    hasher = hashlib.sha256()
    file = safe_open(file_path)
    if file is None:
        raise Exception("Failed to open file after multiple attempts.")
    with file:
        while chunk := file.read(4096):
            hasher.update(chunk)
    return hasher.hexdigest()

@shared_task
def safe_open(file_path, attempts=5, delay=2):
    """Attempt to open a file with retries."""
    for attempt in range(attempts):
        try:
            return open(file_path, 'rb')
        except IOError as e:
            print(f"Attempt {attempt+1}: Unable to open file - {e}")
            time.sleep(delay)
    return None  # or raise an Exception if critical
