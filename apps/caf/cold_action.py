from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from .ColdForensic import ColdForensic
from .ADBCore import ADBCore
import json, re, logging
from apps.home.models import Acquisition

logger = logging.getLogger(__name__)
adb_instance = ADBCore()
cold_forensic_instance = ColdForensic()


def getDevices(request, id):
    if request.method == "GET":
        cold_forensic = ColdForensic()

        if cold_forensic.checkSerialID(id):
            # Determine if the input ID is hashed and, if so, resolve to the serial number
            isHashedIP = cold_forensic.is_hashed_ip_or_not(id)
            serial = (
                cold_forensic.decrypt(id, cold_forensic.secret_key)
                if isHashedIP and cold_forensic.check_if_hashed_ip(id, cold_forensic.secret_key)
                else id
            )
            serialNumber = (
                cold_forensic.decode_bytes_property(
                    cold_forensic.getProp(serial, 'ro.serialno', 'unknown')
                )
                if isHashedIP else id
            )

            # Fetch acquisition history based on serial number
            acquisitionHistory = (
                Acquisition.objects.filter(serial_number=serialNumber)
                .exclude(status='pending')
                .order_by('-date')
            )

            # Prepare acquisition history list
            acquisition_history_list = [
                {
                    'id': acquisition.acquisition_id,
                    'date': acquisition.date,
                    'type': acquisition.acquisition_type,
                    'status': acquisition.status,
                    'percentage': int(
                        100 * (
                                int(acquisition.physical.total_transferred_bytes) /
                                (int(acquisition.physical.partition_size) * 1024)
                        )
                    ) if hasattr(acquisition, 'physical') and acquisition.physical.partition_size else 0
                }
                for acquisition in acquisitionHistory
            ]

            # Fetch device details
            device = cold_forensic.get_devices(request=request, id_or_not=id)

            # Context preparation
            context = {
                'id': id,
                'device': device,
                'acquisitionHistory': acquisition_history_list
            }

            return render(request, 'includes/device_details_more.html', context)

    return JsonResponse({'message': 'No device connected'}, status=404)


def getLogcat(request, id):
    if request.method == "GET":
        device = id
        if len(id) > 15 and cold_forensic_instance.checkSerialID(id):
            device = cold_forensic_instance.decrypt(id, cold_forensic_instance.secret_key)

        (rc, out, err) = adb_instance.adb(['logcat', '-d', '-v', 'brief'], device=device)
        if rc != 0:
            print(err)
            return HttpResponse(err)

        print("Ini isi out: ", type(out))
        return HttpResponse(out)


def postKey(request, id):
    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode())
            logger.debug(f"Received payload: {payload}")
            device = id
            if 'device' in payload and 'key' in payload:
                logger.debug(f"Original device ID: {id}")
                if len(id) > 15 and cold_forensic_instance.checkSerialID(id):
                    device = cold_forensic_instance.decrypt(id, cold_forensic_instance.secret_key)
                    logger.debug(f"Decrypted device ID: {device}")

                key_event = str(payload['key'])
                logger.debug(f"Key event to send: {key_event}")
                rc, _, err = adb_instance.adb(['shell', 'input', 'keyevent', key_event], device=device)
                if rc != 0:
                    logger.error(f"ADB command failed with error: {err}")
                    return JsonResponse({'error': err})

            return JsonResponse({'resuAlt': 'OK'})
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.exception("Unexpected error in postKey")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def postText(request, id):
    if request.method == 'POST':
        payload = json.loads(request.body.decode())  # Ensure decoding for compatibility
        device = id
        if 'device' in payload and 'text' in payload:
            if len(id) > 15 and cold_forensic_instance.checkSerialID(id):
                device = cold_forensic_instance.decrypt(id, cold_forensic_instance.secret_key)

            text = payload['text'].replace(' ', '%s')
            print("New:", device + ' : ' + str(text))
            (rc, _, err) = adb_instance.adb(['shell', 'input', 'text', '"' + text + '"'], device=device)
            print('event done ' + str(rc))
            if rc != 0:
                print(err)
                return JsonResponse({'error': err})

        return JsonResponse({'result': 'OK'})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def postShell(request, id):
    if request.method == "POST":
        payload = json.loads(request.body.decode())  # Ensure decoding for compatibility
        device = id
        out = ""  # Initialize 'out' to avoid undefined variable error

        if 'device' in payload and 'command' in payload:
            if len(id) > 15 and cold_forensic_instance.checkSerialID(id):
                device = cold_forensic_instance.decrypt(id, cold_forensic_instance.secret_key)

            command = payload['command']
            print(device + ' : ' + command)

            (rc, out, err) = adb_instance.adb(['shell', command], device=device)
            print('shell done ' + str(rc))

            if rc != 0:
                print(err)
                return HttpResponse(err)

        return HttpResponse(out)

    return HttpResponse("Invalid request method", status=405)


def getScreenshot(request, id):
    if request.method == "GET":
        device = id
        if len(id) > 15 and cold_forensic_instance.checkSerialID(id):
            device = cold_forensic_instance.decrypt(id, cold_forensic_instance.secret_key)

        # Get device screen resolution
        rc, output, err = adb_instance.adb(['shell', 'wm', 'size'], device=device)
        if rc != 0:
            print(err)
            return HttpResponse(err, status=500)
        else:
            match = re.search(r'Physical size: (\d+)x(\d+)', output)
            if match:
                screen_width = int(match.group(1))
                screen_height = int(match.group(2))
            else:
                # Default to 1080p if unable to parse
                screen_width = 1080
                screen_height = 1920

        (rc, out, err) = adb_instance.adb(['exec-out', 'screencap', '-p'], device=device, binary_output=True)
        if rc != 0:
            print(err)
            return HttpResponse(err, status=500)

        # Return the image along with screen dimensions in headers
        response = HttpResponse(out, content_type="image/png")
        response['X-Screen-Width'] = screen_width
        response['X-Screen-Height'] = screen_height
        return response
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def simulate_touch(request, device_id):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            x = data.get('x')
            y = data.get('y')

            if x is None or y is None:
                return JsonResponse({'error': 'Coordinates not provided'}, status=400)

            # Decrypt device ID if necessary
            device = device_id
            if len(device_id) > 15 and cold_forensic_instance.checkSerialID(device_id):
                device = cold_forensic_instance.decrypt(device_id, cold_forensic_instance.secret_key)

            # Build the input tap command
            # The input command for simulating touch is: input tap x y
            command = ['shell', 'input', 'tap', str(x), str(y)]
            rc, out, err = adb_instance.adb(command, device=device)

            if rc != 0:
                return JsonResponse({'error': 'Failed to simulate touch event', 'details': err}, status=500)

            return JsonResponse({'status': 'success', 'x': x, 'y': y})
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)