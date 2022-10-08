#by al3x_ github.com/al3x-xx

import socket, struct, ipaddress, platform

class stun:
    def __init__(self, ignoreList: list) -> None:
        self.__ignoreList: list = ignoreList
        self.__tempList: list = []
        self.__ipList: list = []

    def __processXorIP(self, ip: int) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(ip ^ 0x2112A442)

    def __appendTempListRet(self, ip: int) -> bool:
        self.__tempList.append(ip)
        return True

    def __checkIgnoreIP(self, ip: ipaddress.IPv4Address) -> bool:
        if (ip_ := int(ip)) in self.__tempList: return True
        if not ip.is_global: return self.__appendTempListRet(ip_)
        for buf in self.__ignoreList:
            if ip in ipaddress.IPv4Network(buf):
                return self.__appendTempListRet(ip_)
        return False

    def _processSTUN(self, buf: bytes) -> None:
        if len(buf) >= 40 and buf[12:16] == b"\x21\x12\xA4\x42" and struct.unpack("!H", buf[8:10])[0] == 0x8:
            if struct.unpack("!H", buf[28:30])[0] == 0x12:
                ip: ipaddress.IPv4Address = self.__processXorIP(struct.unpack("!I", buf[36:40])[0])
                if not (ip_ := str(ip)) in self.__ipList and not self.__checkIgnoreIP(ip):
                    print(f"ip: {ip_}")
                    self.__ipList.append(ip_)

    def getIPList(self) -> str:
        return "\n".join(self.__ipList) + "\n"

class sniffer(stun):
    def __init__(self, ignoreList: list) -> None:
        super().__init__(ignoreList)
        self.__isWin: bool = platform.system() == "Windows"
        self.__s: socket.socket = self.__createSocket()

    def __createSocket(self) -> socket.socket:
        if self.__isWin:
            s: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((socket.gethostname(), 0))
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return s
        else:
            return socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x3))

    def __getIPhdrProtocolOffset(self, buf: bytes) -> bytes:
        return buf[self.__isWin and 9 or 23:]

    def startSniffer(self) -> None:
        try:
            while True:
                buf: bytes = self.__s.recvfrom(0x1000D)[0]
                if (buf := self.__getIPhdrProtocolOffset(buf)) and buf[0] == 17:
                    self._processSTUN(buf[11:])
        except KeyboardInterrupt:
            pass

def getIgnoreList() -> list:
    with open("ignorelist.txt", "r") as f:
        return f.read().splitlines()

def saveLog(ipList: str) -> None:
    with open("log.txt", "a") as f:
        f.write(ipList)

def main() -> None:
    sniffer_: sniffer = sniffer(getIgnoreList())
    sniffer_.startSniffer()
    if (ipList := sniffer_.getIPList()) != "\n":
        saveLog(ipList)

main()