from os import system as sys
from platform import system
from sys import executable


def run():
    runtimeOS = system()
    if runtimeOS == "Windows":
        sys("start /B client.exe \"%s\"" % executable)
    elif runtimeOS == "Linux":
        sys("./client \"%s\"" % executable)
    else:
        print("OS not supported")


if __name__ == '__main__':
    run()
