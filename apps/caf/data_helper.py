from dataclasses import dataclass, field


@dataclass
class ChatData:
    ContentID: str
    ContentInfo: dict = field(default_factory=dict)
    ContentWith: str = ""
    ContentWithUserID: str = ""
    ContentWithUserFullName: str = ""


@dataclass
class Network:
    connected: bool
    ssid: str


@dataclass
class Battery:
    plugged: str
    level: int
    status: int
    health: str


@dataclass
class Screen:
    width: int
    height: int
    orientation: int
    density: int


@dataclass
class DeviceProperties:
    id: str
    serial: str
    isWiFi: bool
    isRooted: bool
    manufacturer: str
    model: str
    sdk: str
    IP: str
    timezone: str
    product: str
    security_patch: str
    api_level: str
    SELinux: str
    AndroidID: str
    operator: str
    IMEI: str
    network: Network
    battery: Battery
    screen: Screen

