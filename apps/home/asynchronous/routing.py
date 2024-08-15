from django.urls import re_path
from . import consumers

websocket_urlpatterns =[
    re_path(r'ws/progress/(?P<serial_id>[^/]+)/physical-acquisition', consumers.ProgressConsumer.as_asgi())
]
