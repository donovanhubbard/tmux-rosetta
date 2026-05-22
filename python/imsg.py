#!/usr/env/bin python3

from enum import Enum

class Imsg:
    def __init__(self):
        self.pid = None
        self.comm = None
        self.fd = None
        self.header = ImsgHeader()
        self.payload = None

class ImsgHeader:
    HEADER_LENGTH = 16 # bytes
    def __init__(self):
        self.type = None
        self.len = None
        self.peerid = None
        self.pid = None

class ImsgType(Enum):
    MSG_VERSION = 12 
    MSG_IDENTIFY_FLAGS = 100 
    MSG_IDENTIFY_TERM = 101 
    MSG_IDENTIFY_TTYNAME = 102 
    MSG_IDENTIFY_OLDCWD = 103
    MSG_IDENTIFY_STDIN = 104 
    MSG_IDENTIFY_ENVIRON = 105 
    MSG_IDENTIFY_DONE = 106 
    MSG_IDENTIFY_CLIENTPID = 107 
    MSG_IDENTIFY_CWD = 108 
    MSG_IDENTIFY_FEATURES = 109 
    MSG_IDENTIFY_STDOUT = 110 
    MSG_IDENTIFY_LONGFLAGS = 111 
    MSG_IDENTIFY_TERMINFO = 112 
    MSG_COMMAND = 200 
    MSG_DETACH = 201 
    MSG_DETACHKILL = 202 
    MSG_EXIT = 203 
    MSG_EXITED = 204 
    MSG_EXITING = 205 
    MSG_LOCK = 206 
    MSG_READY = 207 
    MSG_RESIZE = 208 
    MSG_SHELL = 209 
    MSG_SHUTDOWN = 210 
    MSG_OLDSTDERR = 211
    MSG_OLDSTDIN = 212
    MSG_OLDSTDOUT = 213
    MSG_SUSPEND = 214 
    MSG_UNLOCK = 215 
    MSG_WAKEUP = 216 
    MSG_EXEC = 217 
    MSG_FLAGS = 218 
    MSG_READ_OPEN = 300  
    MSG_READ  = 301 
    MSG_READ_DONE = 302 
    MSG_WRITE_OPEN = 303 
    MSG_WRITE = 304 
    MSG_WRITE_READY = 305 
    MSG_WRITE_CLOSE = 306 
    MSG_READ_CANCEL = 307


