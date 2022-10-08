#by al3x_ github.com/al3x-xx

import socket, struct, ipaddress, platform

class stun:
    __ipList, __tempList = [], []
    
    def __init__(self, ignoreList: list) -> None:
        self.__ignoreList = ignoreList

    def __processXorIP(self, ip: bytes) -> str:
        return str(ipaddress.IPv4Address(0x2112A442 ^ ip))

    def __appendTempListRet(self, ip: str) -> bool:
        self.__tempList.append(ip)
        return True

    def __checkIgnoreIP(self, ip: str) -> bool:
        if ip in self.__tempList: return True
        if not ipaddress.ip_address(ip).is_global: return self.__appendTempListRet(ip)
        for buf in self.__ignoreList:
            if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(buf):
                return self.__appendTempListRet(ip)
        return False

    def _processSTUN(self, buf: bytes) -> None:
        if struct.unpack("!H", buf[8:10])[0] == 0x8 and buf[12:16] == b"\x21\x12\xA4\x42":
            if struct.unpack("!H", buf[28:30])[0] == 0x12:
                ip = self.__processXorIP(struct.unpack("!I", buf[36:40])[0])
                if not ip in self.__ipList and not self.__checkIgnoreIP(ip):
                    print(f"ip: {ip}")
                    self.__ipList.append(ip)

    def getIPList(self) -> str:
        return "\n".join(self.__ipList) + "\n"

class sniffer(stun):
    def __init__(self, ignoreList: list) -> None:
        super().__init__(ignoreList)
        self.__isWin = platform.system() == "Windows"
        self.__s = self.__createSocket()

    def __createSocket(self) -> socket:
        if self.__isWin:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((socket.gethostbyname(socket.gethostname()), 0))
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return s
        else:
            return socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x3))

    def __getIPhdrProtocolOffset(self, buf: bytes) -> bytes:
        return buf[self.__isWin and 9 or 23:]

    def startSniff(self) -> None:
        try:
            while True:
                buf: bytes = self.__s.recvfrom(0x10000)[0]
                buf = self.__getIPhdrProtocolOffset(buf)
                if buf[0] == 17:
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
    sniff = sniffer(getIgnoreList())
    sniff.startSniff()
    ipList = sniff.getIPList()
    if ipList != "\n":
        saveLog(ipList)

main()
