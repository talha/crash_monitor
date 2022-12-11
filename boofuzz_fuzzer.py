from boofuzz import *
import socket
import platform
import subprocess
import time
import random
from time import sleep


# boofuzz fuzzing script for vulnserver (https://github.com/stephenbradshaw/vulnserver)
# external monitor depends on (https://github.com/talha/crash_monitor)

RHOST, RPORT = "223.223.224.132", 9999 # vulnserver IP, PORT
M_RHOST, M_RPORT = "223.223.224.132", 4444 # crash monitor IP, PORT


VALID_COMMANDS = [
    "STATS", "RTIME", "LTIME", "SRUN", "TRUN", "GMON", "GDOG", "KSTET", "HTER", "LTER", "KSTAN"
]
"""
VALID_COMMANDS = [
    "TRUN"
]
"""

class CustomMonitor(BaseMonitor):
    """
    External instrumentation class
    Monitor a target which doesn't support a debugger, allowing external
    commands to be called.

    .. deprecated:: 0.2.0
       This class is a shortcut with limited capabilities. It should be
       substituted by custom classes that implement BaseMonitor.
    """

    def __init__(self, pre=None, post=None, start=None, stop=None):
        """
        @type  pre:   def
        @param pre:   Callback called before each test case
        @type  post:  def
        @param post:  Callback called after each test case for instrumentation. Must return True if the target is still
                      active, False otherwise.
        @type  start: def
        @param start: Callback called to start the target
        @type  stop:  def
        @param stop:  Callback called to stop the target
        """
        super(CustomMonitor, self).__init__()

        self.pre = pre
        self.post = post
        self.start = start
        self.stop = stop
        self.__dbg_flag = False

    def debug(self, msg):
        """
        Print a debug message.
        """

        if self.__dbg_flag:
            print("EXT-INSTR> %s" % msg)

    # noinspection PyUnusedLocal
    def pre_send(self, target=None, fuzz_data_logger=None, session=None):
        """
        This routine is called before the fuzzer transmits a test case and ensure the target is alive.
        """

        if self.pre:
            self.pre()

    def post_send(self, target=None, fuzz_data_logger=None, session=None):
        """
        This routine is called after the fuzzer transmits a test case and returns the status of the target.

        @rtype:  Boolean
        @return: Return True if the target is still active, False otherwise.
        """

        # total_mutant_index = session.total_mutant_index

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((M_RHOST, M_RPORT))
            crash_status = sock.recv(1024)

        if crash_status == b"1":
            print("Program has crashed")
            return False
        else:
            print("Program is still running")
            return True

    def start_target(self):
        """
        Start up the target. Called when post_send failed.
        Returns success of failure of the action
        If no method defined, false is returned
        """

        if self.start:
            return self.start()
        else:
            return False

    def stop_target(self):
        """
        Stop the target.
        """

        if self.stop:
            self.stop()

    def restart_target(self, target=None, fuzz_data_logger=None, session=None):
        self.stop_target()
        return self.start_target()

    def get_crash_synopsis(self):
        """
        Return the last recorded crash synopsis.

        @rtype:  String
        @return: Synopsis of last recorded crash.
        """

        return "External instrumentation detects a crash...\n"

    def __repr__(self):
        return "CustomMonitor#{}".format(id(self))

    def post_start_target(self, target=None, fuzz_data_logger=None, session=None):
        """Called after a target is started or restarted."""
        return

    def retrieve_data(self):
        """
        Called to retrieve data independent of whether the current fuzz node crashed
        the target or not. Called before the fuzzer proceeds to a new testcase.

        You SHOULD return any auxiliary data that should be recorded. The data MUST
        be serializable, e.g. bytestring.

        Defaults to return None.
        """
        return None

    def set_options(self, *args, **kwargs):
        """
        Called to set options for your monitor (e.g. local crash dump storage).
        \\*args and \\*\\*kwargs can be explicitly specified by implementing classes,
        however you SHOULD ignore any kwargs you do not recognize.

        Defaults to no effect.

        :returns: None
        """
        return


custom_monitor = CustomMonitor()
a = random.getrandbits(64)

session = Session(
    target=Target(
        connection=TCPSocketConnection(RHOST, RPORT),
        monitors=[custom_monitor]
    ),
    db_filename="boofuzz_fuzzer_{}.db".format(a),
    console_gui=False,
    ignore_connection_reset=True,
    ignore_connection_aborted=True,
)


ftp = Request("fuzz", children=(
        #String("command", fuzz_values = VALID_COMMANDS, fuzzable = False),
        Group("key", values=VALID_COMMANDS),
        Delim("space", " ", fuzzable=False),
        String("value", "FUZZ"),
    )
)

session.connect(ftp)
session.fuzz()
