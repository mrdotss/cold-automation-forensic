from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .ColdForensic import ColdForensic
from .ADBCore import ADBCore
import json
import logging


logger = logging.getLogger(__name__)
adb_instance = ADBCore()
cold_forensic_instance = ColdForensic()

def getDevices(request, id):
    return cold_forensic_instance.get_devices(request=request, id_or_not=id)


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


@csrf_exempt
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

            return JsonResponse({'result': 'OK'})
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.exception("Unexpected error in postKey")
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
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


@csrf_exempt
def postShell(request, id):
    if request.method == "POST":
        payload = json.loads(request.body.decode())  # Ensure decoding for compatibility
        device = id
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


def getScreenshot(request, id):
    if request.method == "GET":
        device = id
        if len(id) > 15 and cold_forensic_instance.checkSerialID(id):
            device = cold_forensic_instance.decrypt(id, cold_forensic_instance.secret_key)

        (rc, out, err) = adb_instance.adb(['exec-out', 'screencap', '-p'], device=device, binary_output=True)
        if rc != 0:
            print(err)
            return HttpResponse(err, status=500)

        return HttpResponse(out, content_type="image/png")
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)