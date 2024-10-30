from channels.generic.websocket import AsyncWebsocketConsumer
import json
from .redis_helper import set_value, delete_value

class ProgressConsumer(AsyncWebsocketConsumer):

    # New method to handle acquisition_error messages
    async def acquisition_error(self, event):
        """
        Sends an acquisition error message to the WebSocket.

        Parameters:
        - event (dict): The event data containing the error message.
        """
        await self.send(text_data=json.dumps({
            'type': 'acquisition_error',
            'message': event.get('message', 'An unknown error occurred during acquisition.')
        }))

    async def acquisition_completed(self, event):
        """
        Sends an acquisition completed message to the WebSocket.

        Parameters:
        - event (dict): The event data containing the completion message and report location.
        """
        await self.send(text_data=json.dumps({
            'type': 'acquisition_completed',
            'message': event.get('message', 'Acquisition completed successfully.'),
            'report_location': event.get('report_location')
        }))

    async def connect(self):
        self.unique_link = self.scope['url_route']['kwargs']['unique_link']
        self.room_group_name = f'acquisition-progress_{self.unique_link}'

        # Store the connection ID and group name in Redis
        connection_id = self.channel_name
        set_value(connection_id, self.room_group_name)

        print("Connected:", self.room_group_name)
        print("Connection ID:", connection_id)

        await self.channel_layer.group_add(self.room_group_name, self.channel_name)
        await self.accept()

        await self.send(text_data=json.dumps({'message': 'Reconnected'}))

        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': 'Connected to the server',
            'channel_name': self.channel_name
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

        print("Disconnected:", self.room_group_name)
        delete_value(self.channel_name)

        return super().disconnect(close_code)

    async def update_progress(self, event):
        print("Progress function called with event:", event)
        progress = event.get('progress', None)
        estimated = event.get('estimated_time_remaining', None)
        message = event.get('message', 'Acquisition in progress...')

        await self.send(text_data=json.dumps({
            'type': 'update_progress',
            'update_progress': progress,
            'estimated_time_remaining': estimated,
            'message': message
        }))

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        isReady = text_data_json.get('pre-setup', False)
        isStart = text_data_json.get('start', False)
        isProgress = text_data_json.get('send_progress', False)
        message_type = text_data_json.get('type')

        if isReady:
            print("isReady:", isReady)
            await self.send(text_data=json.dumps({
                'type': 'preparing',
                'message': 'Setting up the acquisition...'
            }))

        if isStart:
            print("isStart:", isStart)
            await self.send(text_data=json.dumps({
                'type': 'starting',
                'message': 'Starting the acquisition...'
            }))

        if isProgress:
            print("isProgress:", isProgress)
            await self.send(text_data=json.dumps({
                'type': 'send_progress',
                'message': 'Acquisition in progress...'
            }))

        if message_type == 'acquisition_error':
            await self.acquisition_error(text_data_json)

        if message_type == 'acquisition_completed':
            await self.acquisition_completed(text_data_json)
