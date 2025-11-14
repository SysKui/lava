# Copyright (C) 2014 Linaro Limited
#
# Author: Neil Williams <neil.williams@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
from typing import TYPE_CHECKING, List

import pexpect
from lava_common.constants import DISPATCHER_DOWNLOAD_DIR, SYS_CLASS_KVM
from lava_common.exceptions import JobError
from lava_common.utils import debian_package_arch, debian_package_version

from lava_dispatcher.action import Action, Pipeline
from lava_dispatcher.actions.boot import AutoLoginAction, BootHasMixin, OverlayUnpack
from lava_dispatcher.actions.boot.environment import ExportDeviceEnvironment
from lava_dispatcher.connections.serial import QemuSession
from lava_dispatcher.logical import RetryAction
from lava_dispatcher.shell import ExpectShellSession, ShellCommand
from lava_dispatcher.utils.docker import DockerRun
from lava_dispatcher.utils.network import dispatcher_ip
from lava_dispatcher.utils.shell import which
from lava_dispatcher.utils.strings import substitute

if TYPE_CHECKING:
    from lava_dispatcher.job import Job


class BootQEMUImageAction(BootHasMixin, RetryAction):
    name = "boot-image-retry"
    description = "boot image with retry"
    summary = "boot with retry"

    def populate(self, parameters):
        self.pipeline = Pipeline(parent=self, job=self.job, parameters=parameters)
        self.pipeline.add_action(BootQemuRetry(self.job))
        if self.has_prompts(parameters):
            self.pipeline.add_action(AutoLoginAction(self.job))
            if self.test_has_shell(parameters):
                self.pipeline.add_action(ExpectShellSession(self.job))
                if "transfer_overlay" in parameters:
                    self.pipeline.add_action(OverlayUnpack(self.job))
                self.pipeline.add_action(ExportDeviceEnvironment(self.job))


class BootQemuRetry(RetryAction):
    name = "boot-qemu-image"
    description = "boot image using QEMU command line"
    summary = "boot QEMU image"

    def populate(self, parameters):
        self.pipeline = Pipeline(parent=self, job=self.job, parameters=parameters)
        self.pipeline.add_action(CallQemuAction(self.job))


class DelayedTaskExecutor:
    """Executor for delayed task execution using threading.Timer"""

    def __init__(self, interval, callback, *args, **kwargs):
        """
        Initialize delayed task executor.

        :param interval: Delay interval in seconds
        :param callback: Callback function to execute
        :param args: Positional arguments for callback
        :param kwargs: Keyword arguments for callback
        """
        self._interval = interval
        self._callback = callback
        self._args = args
        self._kwargs = kwargs
        self._timer = None

    def start(self):
        """Start the delayed task timer"""
        self._timer = threading.Timer(self._interval, self._execute)
        self._timer.daemon = True
        self._timer.start()

    def _execute(self):
        """Execute the callback function"""
        self._callback(*self._args, **self._kwargs)

    def cancel(self):
        """Cancel the delayed task if not yet executed"""
        if self._timer is not None:
            self._timer.cancel()

    def __enter__(self):
        """Support context manager protocol"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure timer is cancelled when exiting context"""
        self.cancel()
        return False


# Maintain backward compatibility
TimerWithCallback = DelayedTaskExecutor


class BaseUnixSocketClient:
    """Base class for Unix Domain Socket clients with common connection logic"""

    def __init__(self, server_address, logger):
        """
        Initialize socket client.

        :param server_address: Unix socket file path
        :param logger: Logger instance
        """
        self._server_address = server_address
        self._logger = logger
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def connect(self):
        """Establish connection to socket server"""
        try:
            self._logger.info(f"Attempting to connect to {self._server_address}")
            self._sock.connect(self._server_address)
            self._logger.info(f"Successfully connected to {self._server_address}")
            return True
        except Exception as e:
            self._logger.error(f"Connection failed: {e}")
            return False

    def send(self, data: str):
        """Send string data to socket server"""
        self._sock.sendall(data.encode())

    def receive(self, buffer_size=1024):
        """Receive data from socket server"""
        return self._sock.recv(buffer_size)

    def close(self):
        """Close the socket connection"""
        try:
            self._sock.close()
        except Exception as e:
            self._logger.warning(f"Error closing socket: {e}")

    def __del__(self):
        """Cleanup socket on deletion"""
        self.close()


class QMPEventHandler:
    """Handler for QEMU Machine Protocol (QMP) events"""

    def __init__(self, logger, shell, dump_dir="/var/log/qemu-vmcores"):
        """
        Initialize QMP event handler.

        :param logger: Logger instance
        :param shell: pexpect.spawn shell for QEMU interaction
        :param dump_dir: Directory to store vmcore dumps
        """
        self._logger = logger
        self._shell = shell
        self._panic_count = 0
        self._dump_dir = dump_dir
        self._qmp_socket = None

    def set_qmp_socket(self, qmp_socket):
        """
        Set the QMP socket for sending commands.

        :param qmp_socket: Socket connection to QMP server
        """
        self._qmp_socket = qmp_socket

    def _execute_dump_guest_memory(self):
        """
        Execute dump-guest-memory command via QMP.

        Generates a vmcore file that can be analyzed with crash utility.
        """
        if not self._qmp_socket:
            self._logger.error("QMP socket not available for dump-guest-memory")
            return

        # Create dump directory if it doesn't exist
        os.makedirs(self._dump_dir, exist_ok=True)

        # Generate filename with timestamp
        from datetime import datetime

        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        dump_file = os.path.join(self._dump_dir, f"vmcore-{timestamp}.vmcore")

        # Prepare dump-guest-memory command
        # Using paging=True for better crash/gdb compatibility
        dump_cmd = {
            "execute": "dump-guest-memory",
            "arguments": {"paging": True, "protocol": f"file:{dump_file}"},
        }

        try:
            self._logger.info(f"Executing dump-guest-memory -> {dump_file}")

            # Send command to QMP
            cmd_json = json.dumps(dump_cmd)
            self._qmp_socket.sendall(cmd_json.encode())

            # Wait for response
            response_data = self._qmp_socket.recv(4096)
            if response_data:
                response = json.loads(response_data.decode())
                self._logger.info(f"dump-guest-memory response: {response}")
            else:
                self._logger.warning("No response from dump-guest-memory command")

        except Exception as e:
            self._logger.error(f"Failed to execute dump-guest-memory: {e}")

    def handle_event(self, event):
        """
        Process QMP event.

        :param event: Parsed JSON event dictionary
        """
        event_name = event.get("event", "")

        if event_name in ("GUEST_PANICKED", "GUEST_CRASHLOADED"):
            self._panic_count += 1
            self._logger.debug(
                "QEMU panic/crash detected! Event: %s, Count: %d",
                event_name,
                self._panic_count,
            )

            # Dump guest memory for crash analysis
            self._execute_dump_guest_memory()

            # Send enter to QEMU when it restores to match pexpect prompt
            self._shell.send("\r")
            self._logger.debug("Sent enter to QEMU shell")

    @property
    def panic_count(self):
        """Get the current panic count"""
        return self._panic_count


class QMPMonitor(BaseUnixSocketClient):
    """Monitor for QEMU QMP events, specifically tracking panic events"""

    def __init__(self, server_address, logger, shell, dump_dir="/var/log/qemu-vmcores"):
        """
        Initialize QMP monitor.

        :param server_address: QMP socket file path
        :param logger: Logger instance
        :param shell: pexpect.spawn shell for QEMU interaction
        :param dump_dir: Directory to store vmcore dumps
        """
        super().__init__(server_address, logger)
        self._event_handler = QMPEventHandler(logger, shell, dump_dir)
        self._max_listen_time = 300  # 5 minutes
        self._recv_timeout = 5

    def listen(self):
        """Listen for QMP events and process them"""
        buffer = ""
        self._sock.settimeout(self._recv_timeout)
        start_time = time.time()

        # Enable QMP capabilities first
        try:
            self._sock.sendall(b'{"execute": "qmp_capabilities"}')
            # Read QMP greeting and capability response
            greeting = self._sock.recv(1024)
            self._logger.debug(f"QMP greeting: {greeting.decode()}")
        except Exception as e:
            self._logger.error(f"Failed to enable QMP capabilities: {e}")
            return

        # Set the socket for dump operations
        self._event_handler.set_qmp_socket(self._sock)

        try:
            while time.time() - start_time < self._max_listen_time:
                try:
                    data = self._sock.recv(1024)
                    if not data:
                        self._logger.debug("Connection closed by remote")
                        break

                    buffer += data.decode()
                    events, buffer = self._parse_json_buffer(buffer)

                    for event in events:
                        self._event_handler.handle_event(event)

                except socket.timeout:
                    continue
                except Exception as e:
                    self._logger.error(f"Error in socket listen: {str(e)}")
                    break
        finally:
            self._logger.debug(f"Listen ended with panic count: {self.panic_count}")

    @property
    def panic_count(self):
        """Get the total panic count"""
        return self._event_handler.panic_count

    @staticmethod
    def _parse_json_buffer(buffer):
        """
        Parse multiple JSON objects from buffer.

        :param buffer: String buffer containing JSON data
        :return: Tuple of (list of parsed objects, remaining buffer)
        """
        results = []
        while buffer:
            try:
                obj, idx = json.JSONDecoder().raw_decode(buffer)
                results.append(obj)
                buffer = buffer[idx:].lstrip()
            except json.JSONDecodeError:
                break
        return results, buffer


# Maintain backward compatibility
class SocketClient(QMPMonitor):
    """Backward compatible alias for QMPMonitor"""

    def __init__(self, server_address, logger, shell, dump_dir="/var/log/qemu-vmcores"):
        super().__init__(server_address, logger, shell, dump_dir)
        # Keep original attribute names for compatibility
        self.panic = 0
        self.shell = shell
        self.logger = logger
        self.server_address = server_address
        self.sock = self._sock

    @property
    def panic(self):
        return self._event_handler.panic_count

    @panic.setter
    def panic(self, value):
        self._event_handler._panic_count = value


class BaseUnixSocketServer:
    """Base class for Unix Domain Socket servers"""

    def __init__(self, socket_address, logger):
        """
        Initialize socket server.

        :param socket_address: Unix socket file path
        :param logger: Logger instance
        """
        self._socket_address = socket_address
        self._logger = logger
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._cleanup_socket_file()

    def _cleanup_socket_file(self):
        """Remove existing socket file if present"""
        try:
            if os.path.exists(self._socket_address):
                os.unlink(self._socket_address)
                self._logger.debug(
                    f"Removed existing socket file: {self._socket_address}"
                )
        except OSError as e:
            self._logger.warning(f"Failed to remove socket file: {e}")

    def bind_and_listen(self):
        """Bind socket and start listening"""
        self._sock.bind(self._socket_address)
        self._sock.listen()
        self._logger.debug(f"Server listening on {self._socket_address}")

    def accept_connection(self):
        """Accept incoming connection"""
        conn, addr = self._sock.accept()
        self._logger.debug(f"Accepted connection from {addr}")
        return conn, addr

    def close(self):
        """Close the server socket"""
        try:
            self._sock.close()
            self._cleanup_socket_file()
        except Exception as e:
            self._logger.warning(f"Error closing server socket: {e}")


class SerialCommandForwarder:
    """Forwards commands from socket to QEMU serial shell"""

    def __init__(self, shell, logger):
        """
        Initialize command forwarder.

        :param shell: QEMU pexpect.spawn object
        :param logger: Logger instance
        """
        self._shell = shell
        self._logger = logger

    def forward(self, data):
        """
        Forward data to QEMU shell.

        :param data: Raw bytes data to forward
        """
        decoded_data = data.decode()
        self._shell.send(decoded_data)
        self._logger.debug(f"Forwarded to QEMU: {decoded_data}")


class SerialSocketServer(BaseUnixSocketServer):
    """Unix socket server that forwards commands to QEMU serial interface"""

    def __init__(self, shell, logger, socket_address):
        """
        Initialize serial socket server.

        :param shell: QEMU pexpect.spawn object
        :param logger: Logger instance
        :param socket_address: Unix socket file path
        """
        super().__init__(socket_address, logger)
        self._forwarder = SerialCommandForwarder(shell, logger)

    def handle_request(self, data):
        """
        Handle incoming request data.

        :param data: Raw bytes data from client
        """
        self._forwarder.forward(data)

    def listen(self):
        """Listen for incoming connections and handle requests"""
        self.bind_and_listen()
        while True:
            conn, addr = self.accept_connection()
            try:
                data = conn.recv(1024)
                if data:
                    self.handle_request(data)
            except Exception as e:
                self._logger.error(f"Error handling request: {e}")
            finally:
                conn.close()


# Maintain backward compatibility
class SocketServerForSerial(SerialSocketServer):
    """Backward compatible alias for SerialSocketServer"""

    def __init__(self, shell, logger, socket_address):
        super().__init__(shell, logger, socket_address)
        # Keep original attribute names for compatibility
        self.shell = shell
        self.logger = logger
        self.socket_address = socket_address
        self.sock = self._sock


# Client to inject faults to user's app
# TODO: refactor this class
class SocketClient_app:
    def __init__(
        self,
        sever_address,
        logger,
        app_command,
        flipshell,
        log_stdout,
        log_stderr,
        port,
        host,
        username,
        password,
        prompts,
        guest_send_path,
    ):
        """
        :param sever_address: QMP socket file path
        :param logger: logger to use, commonly is LAVA logger, which can print log to Web
        :param appcommand: command to launch app that need to inject faults
        :param flipshell: The command to inject faults via gdb
        :param log_stdout: gdb log stdout
        :param log_stderr: gdb log stderr
        :param port: port for ssh
        :param host: host for ssh
        :param username: username for ssh
        :param password: password for ssh
        :param prompts: prompts for pexcept
        :param guest_send_path: guest_send.sh path in rootfs
        """

        self.flipshell = flipshell
        self.log_stdout = log_stdout
        self.log_stderr = log_stderr
        self.logger = logger
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.prompts = prompts
        self.guest_send_path = guest_send_path
        # TODO: guest_send.sh should store out of guest rootfs
        self.appcommand = None
        if app_command:
            self.appcommand = f"nohup bash {self.guest_send_path} {app_command} > /tmp/guest.log 2>&1 &"
        # virtio-serial-pci socket
        self.sever_address = sever_address
        socket_family = socket.AF_UNIX
        socket_type = socket.SOCK_STREAM

        self.sock = socket.socket(socket_family, socket_type)

        # try:
        #     self.sock.connect(self.sever_address)
        # except Exception as e:
        #     raise e

    def run_flipshell(self):
        with open(self.log_stdout, "w") as stdout, open(self.log_stderr, "w") as stderr:
            process = subprocess.Popen(self.flipshell, stdout=stdout, stderr=stderr)
            self.logger.debug(
                "Spawn a thread to inject faul ts, Command is %s", self.flipshell
            )
            process.wait()
            self.logger.debug("Fault injection completed.")

    def listen(self):
        """Listen the socket server and get the response"""

        def is_port_listening(host, port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            try:
                sock.connect((host, int(port)))
            except (socket.timeout, socket.error):
                return False

            return True

        self.logger.debug(f"check if port {self.port} is listened")

        # Add timeout mechanism to avoid infinite loop
        max_wait_time = 60  # Wait for maximum of 60 seconds
        start_time = time.time()
        while not is_port_listening(self.host, self.port):
            if time.time() - start_time > max_wait_time:
                self.logger.error(
                    f"Timeout waiting for port {self.port} to be listened"
                )
                return  # Exit function after timeout
            time.sleep(0.5)  # Add short sleep to reduce CPU usage

        self.logger.debug(f"port {self.port} is listened")

        # detech the qemu
        self.logger.debug("check if the qemu is already booted")

        max_retries = 10  # Retry at most 2 time (i.e. 3 attempts in total)
        retry_delay = 5  # Retry interval (seconds)

        # TODO: we can use socket to test if the ssh is usable
        for attempt in range(max_retries + 1):
            try:
                ssh = pexpect.spawn(
                    f"ssh -p {self.port} -o StrictHostKeyChecking=no {self.username}@{self.host}"
                )
                logfile = open("/tmp/sshlogfile.txt", "wb")
                ssh.logfile = logfile
                self.logger.debug(f"now the password is {self.password}")
                ssh.expect(f"{self.username}@{self.host}'s password:", timeout=600)
                self.logger.debug(f"I will pass my password: {self.password}")
                ssh.sendline(self.password)
                ssh.expect(f"{self.prompts}")
                if self.appcommand:
                    ssh.sendline(self.appcommand)
                    ssh.expect(f"{self.prompts}")
                ssh.sendline("exit")
                ssh.close()
                logfile.close()
                break

            except (pexpect.EOF, pexpect.TIMEOUT) as e:
                self.logger.debug(f"Attempt {attempt + 1} failed: {str(e)}")
                if ssh and not ssh.closed:
                    ssh.close()
                if "logfile" in locals() and not logfile.closed:
                    logfile.close()

                if attempt < max_retries:
                    self.logger.debug(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    self.logger.debug("Max retries reached. Giving up.")
                    raise

        # The client has written to the socket and started listening to the host's socket
        self.logger.debug("Connecting to local socket and waiting for guest signal...")

        try:
            self.sock.connect(self.sever_address)
            self.sock.settimeout(60)
            data = self.sock.recv(1024)
            self.logger.debug("Socket recv signal")
            scp = pexpect.spawn(
                f"scp -P {self.port} -o StrictHostKeyChecking=no {self.username}@{self.host}:/root/output.log /root/"
            )
            scp.expect(f"{self.username}@{self.host}'s password: ", timeout=600)
            scp.sendline(str(self.password))
            scp.expect(pexpect.EOF)
            scp.close()
            self.run_flipshell()
        except socket.timeout:
            self.logger.warning("Socket recv timeout, no data received")

        except Exception as e:
            self.logger.error(f"Socket error: {e}")

    def __del__(self):
        """Clean the socket"""
        self.sock.close()


class CallQemuAction(Action):
    name = "execute-qemu"
    description = "call qemu to boot the image"
    summary = "execute qemu to boot the image"

    session_class = QemuSession
    shell_class = ShellCommand

    def __init__(self, job: Job):
        super().__init__(job)
        self.base_sub_command = []
        self.docker = None
        self.sub_command = []
        self.commands = []
        self.methods = None
        self.nfsrootfs = None
        self.qemu_data = {}

    def get_qemu_pkg_suffix(self, arch):
        if arch in ["amd64", "x86_64"]:
            return "x86"
        if arch in ["arm64", "arm", "armhf", "aarch64"]:
            return "arm"
        return ""

    def get_debian_version(self, architecture):
        pkg_suffix = self.get_qemu_pkg_suffix(architecture)
        if pkg_suffix == "":
            return False
        if "docker" in self.parameters:
            # We will find it by get_raw_version()
            return False
        ver_str = debian_package_version(pkg="qemu-system-%s" % pkg_suffix)
        arch_str = debian_package_arch(pkg="qemu-system-%s" % pkg_suffix)
        if ver_str == "":
            return False
        self.qemu_data = {
            "qemu_version": ver_str,
            "host_arch": arch_str,
            "job_arch": architecture,
        }
        self.logger.info(
            "qemu-system-%s, installed at version: %s, host architecture: %s",
            pkg_suffix,
            ver_str,
            arch_str,
        )
        return True

    def get_qemu_arch(self, architecture):
        if architecture == "arm64":
            return "aarch64"
        return architecture

    def get_raw_version(self, architecture):
        if "docker" in self.parameters:
            docker = DockerRun.from_parameters(self.parameters["docker"], self.job)
            ver_strs = docker.run(
                *shlex.split(
                    "qemu-system-%s --version" % self.get_qemu_arch(architecture)
                ),
                action=self,
                capture=True,
            )
        else:
            ver_strs = subprocess.check_output(
                (f"qemu-system-{architecture}", "--version"),
                encoding="utf-8",
                errors="replace",
            )
        # line is QEMU emulator version xxxx
        ver_str = ver_strs.split()[3]
        arch_str = (
            subprocess.check_output(("uname", "-m"))
            .strip()
            .decode("utf-8", errors="replace")
        )
        self.qemu_data = {
            "qemu_version": ver_str,
            "host_arch": arch_str,
            "job_arch": architecture,
        }
        self.logger.info(
            "qemu, installed at version: %s, host architecture: %s", ver_str, arch_str
        )
        return True

    def validate(self):
        super().validate()

        # 'arch' must be defined in job definition context.
        architecture = self.job.parameters.get("context", {}).get("arch")
        if architecture is None:
            raise JobError("Missing 'arch' in job context")
        if "available_architectures" not in self.job.device:
            self.errors = "Device lacks list of available architectures."
        try:
            if architecture not in self.job.device["available_architectures"]:
                self.errors = "Non existing architecture specified in context arch parameter. Please check the device configuration for available options."
                return
        except KeyError:
            self.errors = "Arch parameter must be set in the context section. Please check the device configuration for available architectures."
            return

        if not self.get_debian_version(architecture):
            self.get_raw_version(architecture)

        if self.parameters["method"] in ["qemu", "qemu-nfs"]:
            if "prompts" not in self.parameters:
                if self.test_has_shell(self.parameters):
                    self.errors = "Unable to identify boot prompts from job definition."
        self.methods = self.job.device["actions"]["boot"]["methods"]
        method = self.parameters["method"]
        boot = (
            self.methods["qemu"] if "qemu" in self.methods else self.methods["qemu-nfs"]
        )
        try:
            if "parameters" not in boot or "command" not in boot["parameters"]:
                self.errors = "Invalid device configuration - missing parameters"
            elif not boot["parameters"]["command"]:
                self.errors = "No QEMU binary command found - missing context."
            # if qemu is ran under docker, qemu could not be installed and so which will fail
            qemu_binary = boot["parameters"]["command"]
            if "docker" not in self.parameters:
                qemu_binary = which(qemu_binary)
            self.base_sub_command = [qemu_binary]
            self.base_sub_command.extend(boot["parameters"].get("options", []))
            self.base_sub_command.extend(
                ["%s" % item for item in boot["parameters"].get("extra", [])]
            )
        except AttributeError as exc:
            self.errors = "Unable to parse device options: %s %s" % (
                exc,
                self.job.device["actions"]["boot"]["methods"][method],
            )
        except (KeyError, TypeError):
            self.errors = "Invalid parameters for %s" % self.name

        for label in self.get_namespace_keys("download-action"):
            if label in ["offset", "available_loops", "uefi", "nfsrootfs"]:
                continue
            image_arg = self.get_namespace_data(
                action="download-action", label=label, key="image_arg"
            )
            action_arg = self.get_namespace_data(
                action="download-action", label=label, key="file"
            )
            if not image_arg or not action_arg:
                self.logger.warning("Missing image arg for %s", label)
                continue
            self.commands.append(image_arg)

        # Check for enable-kvm command line option in device configuration.
        if method not in self.job.device["actions"]["boot"]["methods"]:
            self.errors = "Unknown boot method '%s'" % method
            return

        options = self.job.device["actions"]["boot"]["methods"][method]["parameters"][
            "options"
        ]
        if "-enable-kvm" in options:
            # Check if the worker has kvm enabled.
            if not os.path.exists(SYS_CLASS_KVM):
                self.errors = "Device configuration contains -enable-kvm option but kvm module is not enabled."

    def run(self, connection, max_end_time):
        """
        CommandRunner expects a pexpect.spawn connection which is the return value
        of target.device.power_on executed by boot in the old dispatcher.

        In the new pipeline, the pexpect.spawn is a ShellCommand and the
        connection is a ShellSession. CommandRunner inside the ShellSession
        turns the ShellCommand into a runner which the ShellSession uses via ShellSession.run()
        to run commands issued *after* the device has booted.
        pexpect.spawn is one of the raw_connection objects for a Connection class.
        """
        if connection:
            ns_connection = self.get_namespace_data(
                action="shared", label="shared", key="connection", deepcopy=False
            )
            if connection == ns_connection:
                connection.finalise()

        self.sub_command = self.base_sub_command.copy()
        # Generate the sub command
        substitutions = {}
        for label in self.get_namespace_keys("download-action"):
            if label in ["offset", "available_loops", "uefi", "nfsrootfs"]:
                continue
            image_arg = self.get_namespace_data(
                action="download-action", label=label, key="image_arg"
            )
            action_arg = self.get_namespace_data(
                action="download-action", label=label, key="file"
            )
            if image_arg is not None:
                substitutions["{%s}" % label] = action_arg
        substitutions["{NFS_SERVER_IP}"] = dispatcher_ip(
            self.job.parameters["dispatcher"], "nfs"
        )
        self.sub_command.extend(substitute(self.commands, substitutions))
        uefi_dir = self.get_namespace_data(
            action="deployimages", label="image", key="uefi_dir"
        )
        if uefi_dir:
            self.sub_command.extend(["-L", uefi_dir, "-monitor", "none"])

        # initialise the first Connection object, a command line shell into the running QEMU.
        self.results = self.qemu_data
        guest = self.get_namespace_data(
            action="apply-overlay-guest", label="guest", key="filename"
        )
        applied = self.get_namespace_data(
            action="append-overlays", label="guest", key="applied"
        )

        # check for NFS
        if "qemu-nfs" == self.parameters["method"]:
            self.logger.debug("Adding NFS arguments to kernel command line.")
            root_dir = self.get_namespace_data(
                action="extract-rootfs", label="file", key="nfsroot"
            )
            substitutions["{NFSROOTFS}"] = root_dir
            params = self.methods["qemu-nfs"]["parameters"]["append"]
            # console=ttyAMA0 root=/dev/nfs nfsroot=10.3.2.1:/var/lib/lava/dispatcher/tmp/dirname,tcp,hard,intr ip=dhcp
            append = [
                "console=%s" % params["console"],
                "root=/dev/nfs",
                "%s rw" % substitute([params["nfsrootargs"]], substitutions)[0],
                "%s" % params["ipargs"],
            ]
            self.sub_command.append("--append")
            self.sub_command.append('"%s"' % " ".join(append))
        elif guest and not applied:
            self.logger.info("Extending command line for qcow2 test overlay")
            # interface is ide by default in qemu
            interface = self.job.device["actions"]["deploy"]["methods"]["image"][
                "parameters"
            ]["guest"].get("interface", "ide")
            driveid = self.job.device["actions"]["deploy"]["methods"]["image"][
                "parameters"
            ]["guest"].get("driveid", "lavatest")
            self.sub_command.append(
                "-drive format=qcow2,file=%s,media=disk,if=%s,id=%s"
                % (os.path.realpath(guest), interface, driveid)
            )
            # push the mount operation to the test shell pre-command to be run
            # before the test shell tries to execute.
            shell_precommand_list = []
            mountpoint = self.get_namespace_data(
                action="test", label="results", key="lava_test_results_dir"
            )
            uuid = "/dev/disk/by-uuid/%s" % self.get_namespace_data(
                action="apply-overlay-guest", label="guest", key="UUID"
            )
            shell_precommand_list.append("mkdir %s" % mountpoint)
            # prepare_guestfs always uses ext2
            shell_precommand_list.append("mount %s -t ext2 %s" % (uuid, mountpoint))
            # debug line to show the effect of the mount operation
            # also allows time for kernel messages from the mount operation to be processed.
            shell_precommand_list.append("ls -la %s/bin/lava-test-runner" % mountpoint)
            self.set_namespace_data(
                action="test",
                label="lava-test-shell",
                key="pre-command-list",
                value=shell_precommand_list,
            )

        if "docker" in self.parameters:
            self.docker = docker = DockerRun.from_parameters(
                self.parameters["docker"], self.job
            )
            if not self.parameters["docker"].get("container_name"):
                docker.name(
                    "lava-docker-qemu-%s-%s-" % (self.job.job_id, self.level),
                    random_suffix=True,
                )
            docker.interactive()
            docker.tty()
            if "QEMU_AUDIO_DRV" in os.environ:
                docker.environment("QEMU_AUDIO_DRV", os.environ["QEMU_AUDIO_DRV"])
            docker.bind_mount(DISPATCHER_DOWNLOAD_DIR)
            docker.add_device("/dev/kvm", skip_missing=True)
            docker.add_device("/dev/net/tun", skip_missing=True)
            docker.add_docker_run_options("--network=host", "--cap-add=NET_ADMIN")

            # Use docker.binary if provided and fallback to the qemu default binary
            args = [self.parameters["docker"].get("binary", self.sub_command[0])]

            self.logger.info("Pulling docker image")
            docker.prepare(action=self)
            self.sub_command[0] = " ".join(docker.cmdline(*args))

        self.logger.info("Boot command: %s", " ".join(self.sub_command))
        # ShellCommand init, pexpect.spawn class create, qemu start here.
        shell = self.shell_class(
            " ".join(self.sub_command), self.timeout, logger=self.logger
        )
        if shell.exitstatus:
            raise JobError(
                "%s command exited %d: %s"
                % (self.sub_command, shell.exitstatus, shell.readlines())
            )
        self.logger.debug("started a shell command")
        shell_connection = self.session_class(self.job, shell)
        shell_connection = super().run(shell_connection, max_end_time)

        self.set_namespace_data(
            action="shared", label="shared", key="connection", value=shell_connection
        )

        # Inject faults into qemu virtual machine
        try:
            # Get the file system path
            rootfs_url = self.job.parameters["actions"][0]["deploy"]["images"].get(
                "rootfs"
            )["url"]

            fault_inject_params = self.job.parameters["actions"][1]["boot"].get(
                "fault_inject_params", {}
            )
            prompts = self.job.parameters["actions"][1]["boot"].get("prompts", [])[0]
            password = (
                self.job.parameters["actions"][1]["boot"]
                .get("auto_login", {})
                .get("password", "519ailab")
            )
            username = (
                self.job.parameters["actions"][1]["boot"]
                .get("auto_login", {})
                .get("username", "root")
            )
        except Exception as e:
            self.logger.error(f"QEMU boot error: {e}")
            return shell_connection
        # Returns the injected command, otherwise returns an empty list
        inject_command = fault_inject_params.get("commands", [])
        # stdout: /tmp/test.out
        log_stdout = fault_inject_params.get("stdout", "/dev/null")
        # stderr: /tmp/test.err
        log_stderr = fault_inject_params.get("stderr", "/dev/null")
        # Add a delay option
        delayed = fault_inject_params.get("delayed", "")
        # qmp_socket: /tmp/qmp.sock
        socket_file = fault_inject_params.get("qmp_socket", "")
        # /tmp/vm_sync_signal
        socket_app_file = fault_inject_params.get("socket_app", "")
        # User startup command
        app_start_command = fault_inject_params.get("start_command", "")

        flipshell = []
        if inject_command == []:
            # No inject_commands, just return the shell connection
            self.logger.info("No inject commands found, returning shell connection")
            return shell_connection

        is_appinject = False
        # construct flipshell to inject faults
        if shutil.which("gdb-multiarch") is None:
            self.logger.debug("Executable gdb-multiarch is not found")
        else:
            flipshell.extend(
                [
                    "gdb-multiarch",
                    "-q",
                    "-batch",
                    "-ex",
                    "set pagination off",
                ]
            )

            fault_number = 0
            # Determine whether appinject is used and sum the fault numbers
            for cmd in inject_command:
                if cmd.strip().startswith("appinject"):
                    is_appinject = True
                if (
                    cmd.strip().startswith("snapinject")
                    or cmd.strip().startswith("autoinject")
                    or cmd.strip().startswith("appinject")
                ):
                    total_fault_number = int(
                        re.search(r"--total-fault-number\s+(\d+)", cmd).group(1)
                    )
                    self.logger.info(f"fault number add: {total_fault_number}")
                    fault_number += int(total_fault_number)
                    self.logger.info(f"Current fault number: {fault_number}")
                if cmd.strip().startswith("snapinject") and not rootfs_url.endswith(
                    "qcow2"
                ):
                    self.logger.error("Image type is not qcow2")
                else:
                    if is_appinject:
                        # TODO: path to store log should be specify by user
                        flipshell.extend(
                            ["-ex", cmd + " --range-file /root/output.log"]
                        )
                    else:
                        flipshell.extend(["-ex", cmd])
            try:
                os.makedirs("/tmp/" + str(self.job.job_id))
            except FileExistsError:
                self.logger.error(
                    "Dir /tmp/" + str(self.job.job_id) + "already existed"
                )
            with open("/tmp/" + str(self.job.job_id) + "/fault_number.txt", "w") as f:
                f.write(str(fault_number))
            # Add detach and quit to make sure qemu continue
            flipshell.extend(["-ex", "detach", "-ex", "quit"])

        # Split sub_command to the fine-grained list
        cmd_list = " ".join(self.sub_command).split(" ")
        kernel_file = cmd_list[cmd_list.index("-kernel") + 1]

        # Make sure the kernel has the necessary config
        # /root/check-pvpanic is copied when docker image build, if you change the path here, you must change the
        # docker image build script
        if subprocess.run(["sh", "/root/check-pvpanic", kernel_file]).returncode != 0:
            # Kernel should open 'ikconfig', 'pvpanic_pci' and 'pvpanic' config,
            # because driver 'pvpanic-pci' is necessary to get panic event in qemu,
            # and 'ikconfig' is necessary to check whether the pvpanic-pci config is chosen
            self.logger.error("pvpanic_pci and pvpanic config not set")
            return shell_connection

        if not can_support_panic_count(cmd_list):
            self.logger.error("Qemu boot options do not support panic count.")
            return shell_connection

        if not socket_file:
            self.logger.error("No socket file specified for qemu")
            return shell_connection

        # Create a client connected to qemu qmp server to read the panic event and count it
        try:
            # Get dump directory from fault_inject_params or use default
            dump_dir = fault_inject_params.get("vmcore_dir", "/var/log/qemu-vmcores")
            socket_client = SocketClient(socket_file, self.logger, shell, dump_dir)
            panic_thread = threading.Thread(
                target=panic_count, args=(socket_client, self.job.job_id)
            )
            panic_thread.daemon = True  # Set as daemon thread so it will terminate when main program exits
            panic_thread.start()
            self.logger.debug("panic count thread started")
        except Exception as e:
            self.logger.error("Count panic got exception: %s", str(e))

        # Start a thread to listen the socket server and get the response
        try:
            socket_server = SocketServerForSerial(
                shell, self.logger, fault_inject_params.get("serial_socket")
            )
            socket_thread = threading.Thread(target=socket_server.listen, args=())
            socket_thread.daemon = True  # Set as daemon thread so it will terminate when main program exits
            socket_thread.start()
            self.logger.debug("SocketServerForSerial thread started")
        except Exception as e:
            self.logger.error("SocketServerForSerial got exception: %s", str(e))

        if is_appinject:
            try:
                username = (
                    self.job.parameters["actions"][1]["boot"]
                    .get("auto_login", {})
                    .get("username", "root")
                )
                password = (
                    self.job.parameters["actions"][1]["boot"]
                    .get("auto_login", {})
                    .get("password", "519ailab")
                )
                socket_client_app = SocketClient_app(
                    socket_app_file,
                    self.logger,
                    app_start_command,
                    flipshell,
                    log_stdout,
                    log_stderr,
                    username=username,
                    port=fault_inject_params.get("port", "1234"),
                    host=fault_inject_params.get("host", "localhost"),
                    password=password,
                    prompts=prompts,
                    guest_send_path=fault_inject_params.get(
                        "guest_send_path", "/root/guest_send.sh"
                    ),
                )
                app_thread = threading.Thread(
                    target=app_inject, args=(socket_client_app,)
                )
                app_thread.daemon = True  # Set as daemon thread so it will terminate when main program exits
                app_thread.start()
                self.logger.debug("Appinject thread started")
            except Exception as e:
                self.logger.error("Appinject got exception: %s", str(e))
        else:
            params = fault_inject_params
            params["password"] = password
            params["username"] = username
            params["prompts"] = prompts
            if delayed != "":
                # Delayed execution of the inject action
                timer = TimerWithCallback(
                    parse_time_string(delayed),
                    fault_inject_callback,
                    flipshell,
                    log_stdout,
                    log_stderr,
                    self.logger,
                    params,
                )
                timer.start()
            else:
                inject_thread = threading.Thread(
                    target=fault_inject_callback,
                    args=[
                        flipshell,
                        log_stdout,
                        log_stderr,
                        self.logger,
                        params,
                    ],
                    daemon=True,
                )
                inject_thread.start()

        return shell_connection

    def cleanup(self, connection):
        if self.docker is not None:
            self.logger.info("Stopping the qemu container %s", self.docker.__name__)
            self.docker.destroy()


class ServiceReadinessChecker:
    """Generic service readiness checker with support for various protocols"""

    def __init__(self, host, port, timeout=300, check_interval=2):
        """
        Initialize service readiness checker.

        :param host: Service host address
        :param port: Service port number
        :param timeout: Maximum time to wait for service (seconds)
        :param check_interval: Time between checks (seconds)
        """
        self._host = host
        self._port = port
        self._timeout = timeout
        self._check_interval = check_interval

    def wait_for_service(self):
        """
        Wait for service to become ready.

        :return: True if service is ready, False if timeout
        """
        start_time = time.time()

        while time.time() - start_time < self._timeout:
            if self._check_service():
                return True
            time.sleep(self._check_interval)

        return False

    def _check_service(self):
        """
        Check if service is ready.

        :return: True if service is ready, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self._host, self._port))
            sock.close()
            return True
        except Exception:
            return False


class SSHServiceChecker(ServiceReadinessChecker):
    """Specialized checker for SSH service readiness"""

    def _check_service(self):
        """
        Check if SSH service is ready by verifying SSH banner.

        :return: True if SSH service is ready, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self._host, self._port))

            # Read SSH banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore")
            sock.close()

            if banner.startswith("SSH-"):
                print(f"SSH service ready on {self._host}:{self._port}")
                return True

            return False
        except Exception:
            return False


def wait_for_ssh(host, port=22, timeout=300):
    """
    Wait for SSH service to become ready.

    :param host: SSH host address
    :param port: SSH port number
    :param timeout: Maximum wait time in seconds
    :return: True if SSH is ready, False if timeout
    """
    checker = SSHServiceChecker(host, port, timeout)
    return checker.wait_for_service()


class GDBCommandParser:
    """Parser for GDB flipshell commands"""

    @staticmethod
    def parse(flipshell):
        """
        Parse flipshell command list to extract GDB commands.

        :param flipshell: List of command arguments
        :return: List of GDB commands or None if invalid
        """
        if not flipshell or flipshell[0] != "gdb-multiarch":
            return None

        commands = []
        i = 1  # Skip "gdb-multiarch"
        while i < len(flipshell):
            if flipshell[i] == "-ex" and i + 1 < len(flipshell):
                commands.append(flipshell[i + 1])
                i += 2
            elif flipshell[i] in ["-q", "-batch"]:
                i += 1
            else:
                i += 1

        return commands if commands else None


class ProcessManager:
    """Manages pexpect processes with proper resource cleanup"""

    def __init__(self, logger):
        """
        Initialize process manager.

        :param logger: Logger instance
        """
        self._logger = logger
        self._processes = []

    def spawn(self, command, args=None, logfile=None):
        """
        Spawn a new pexpect process.

        :param command: Command to execute
        :param args: Command arguments
        :param logfile: File object for logging
        :return: pexpect process
        """
        if args is None:
            process = pexpect.spawn(command)
        else:
            process = pexpect.spawn(command, args)

        if logfile:
            process.logfile = logfile

        self._processes.append(process)
        return process

    def cleanup(self):
        """Close all managed processes"""
        for process in self._processes:
            if process.isalive():
                try:
                    process.close()
                except Exception as e:
                    self._logger.warning(f"Error closing process: {e}")

    def __enter__(self):
        """Support context manager protocol"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Ensure all processes are cleaned up"""
        self.cleanup()
        return False


class GDBController:
    """Controller for GDB debugging session"""

    def __init__(self, process, logger):
        """
        Initialize GDB controller.

        :param process: pexpect GDB process
        :param logger: Logger instance
        """
        self._process = process
        self._logger = logger
        self._prompt_pattern = r"\(gdb\)\s*"

    def wait_ready(self):
        """Wait for GDB to be ready"""
        self._process.expect(self._prompt_pattern)
        self._logger.debug("GDB started and ready")

    def execute_command(self, command, timeout=30):
        """
        Execute a GDB command.

        :param command: GDB command string
        :param timeout: Command timeout in seconds
        :return: True if successful, False otherwise
        """
        self._logger.debug("Executing GDB command: %s", command)
        self._process.sendline(command)

        try:
            self._process.expect(self._prompt_pattern, timeout=timeout)
            self._logger.debug("GDB command completed: %s", command)
            return True
        except pexpect.TIMEOUT:
            self._logger.warning("Timeout waiting for GDB command: %s", command)
            return False
        except pexpect.EOF:
            self._logger.info("GDB process ended after command: %s", command)
            return False

    def interrupt(self):
        """Send interrupt signal (Ctrl+C) to GDB"""
        self._process.sendcontrol("c")
        self._process.expect(self._prompt_pattern)

    def cont(self):
        """Send continue to GDB"""
        self._process.sendline("continue")


class SSHController:
    """Controller for SSH session to QEMU guest"""

    def __init__(self, process, logger, params):
        """
        Initialize SSH controller.

        :param process: pexpect SSH process
        :param logger: Logger instance
        :param params: SSH connection parameters
        """
        self._process = process
        self._logger = logger
        self._params = params
        self._prompt = params.get("prompt", "root@rros")

    def login(self):
        """Perform SSH login"""
        host = f"{self._params.get('username')}@{self._params.get('ssh_host')}"
        self._process.expect(host)
        self._process.sendline(self._params.get("password", "root"))
        self._process.expect(self._prompt)
        self._logger.debug("SSH connected to QEMU successfully")

    def execute_command(self, command, timeout=30):
        """
        Execute a command via SSH.

        :param command: Command string
        :param timeout: Command timeout in seconds
        :return: True if successful, False otherwise
        """
        self._logger.debug("Executing SSH command: %s", command)
        self._process.sendline(command)

        try:
            self._process.expect(self._prompt, timeout=timeout)
            self._logger.debug("SSH command completed: %s", command)
            return True
        except pexpect.TIMEOUT:
            self._logger.warning("Timeout waiting for SSH command: %s", command)
            return False
        except pexpect.EOF:
            self._logger.info("SSH process ended after command: %s", command)
            return False


class FaultInjectionCoordinator:
    """Coordinates fault injection process using GDB and SSH"""

    def __init__(self, logger, params):
        """
        Initialize fault injection coordinator.

        :param logger: Logger instance
        :param params: Fault injection parameters
        """
        self._logger = logger
        self._params = params
        self._process_manager = ProcessManager(logger)

    def inject(self, gdb_commands, log_stdout, log_stderr):
        """
        Execute fault injection.

        :param gdb_commands: List of GDB commands to execute
        :param log_stdout: Path to stdout log file
        :param log_stderr: Path to stderr log file
        """
        try:
            # Wait for SSH if required
            if self._params.get("inject_after_boot", False):
                if not self._wait_for_boot():
                    return

            # Reserve time for LAVA login
            time.sleep(5)
            self._logger.debug("Starting fault injection, commands: %s", gdb_commands)

            with open(log_stdout, "wb") as stdout, open(log_stderr, "wb") as _stderr:
                # Initialize GDB and SSH
                gdb_process = self._process_manager.spawn(
                    "gdb-multiarch", ["-q"], stdout
                )
                gdb_ctrl = GDBController(gdb_process, self._logger)
                gdb_ctrl.wait_ready()

                ssh_process = self._spawn_ssh(stdout)
                ssh_ctrl = SSHController(ssh_process, self._logger, self._params)
                ssh_ctrl.login()

                # Execute commands
                self._execute_commands(gdb_commands, gdb_ctrl, ssh_ctrl)

        except Exception as e:
            self._logger.error("Error in fault injection: %s", str(e))
        finally:
            self._process_manager.cleanup()
            self._logger.debug("Fault injection completed")

    def _wait_for_boot(self):
        """Wait for system boot completion"""
        ssh_host = self._params.get("ssh_host", "localhost")
        ssh_port = self._params.get("ssh_port", 22)
        self._logger.debug(f"Waiting for boot: {ssh_host}:{ssh_port}")

        if not wait_for_ssh(ssh_host, ssh_port):
            self._logger.error("Wait for boot completion timeout")
            return False
        return True

    def _spawn_ssh(self, logfile):
        """Spawn SSH connection to guest"""
        host = f"{self._params.get('username')}@{self._params.get('ssh_host')}"
        ssh_args = [
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            str(self._params.get("ssh_port")),
            host,
        ]
        return self._process_manager.spawn("ssh", ssh_args, logfile)

    def _execute_commands(self, commands, gdb_ctrl, ssh_ctrl):
        """
        Execute GDB and SSH commands.

        :param commands: List of commands
        :param gdb_ctrl: GDB controller instance
        :param ssh_ctrl: SSH controller instance
        """
        for cmd in commands:
            if cmd.strip().startswith("sshcommand"):
                self._execute_ssh_command(cmd, gdb_ctrl, ssh_ctrl)
            else:
                gdb_ctrl.execute_command(cmd)

    def _execute_ssh_command(self, cmd, gdb_ctrl, ssh_ctrl):
        """
        Execute SSH command through GDB debugging session.

        :param cmd: SSH command string
        :param gdb_ctrl: GDB controller instance
        :param ssh_ctrl: SSH controller instance
        """
        # Interrupt GDB and continue to let SSH command run
        gdb_ctrl.interrupt()
        gdb_ctrl.cont()
        self._logger.debug("Interrupt GDB and send continue to let SSH command run")

        # Extract and execute SSH command
        parts = cmd.split("sshcommand ", 1)
        if len(parts) == 2:
            ssh_ctrl.execute_command(parts[1])
        else:
            self._logger.error("Invalid sshcommand format: %s", cmd)

        # Interrupt GDB again
        gdb_ctrl.interrupt()


def fault_inject_callback(flipshell, log_stdout, log_stderr, logger, params):
    """
    Execute fault injection using GDB and SSH.

    :param flipshell: List of command arguments for gdb-multiarch
    :param log_stdout: Path to stdout log file
    :param log_stderr: Path to stderr log file
    :param logger: Logger instance
    :param params: Fault injection parameters from job definition
    """
    # Parse GDB commands
    parser = GDBCommandParser()
    gdb_commands = parser.parse(flipshell)

    if not gdb_commands:
        logger.error("Invalid flipshell command structure or no commands found")
        return

    # Execute fault injection
    coordinator = FaultInjectionCoordinator(logger, params)
    coordinator.inject(gdb_commands, log_stdout, log_stderr)


def parse_time_string(time_str):
    """
    Parse time string to second float number

    :param time_str: time string, like '1s', '2ms', '3us'
    :return: second float number
    """

    match = re.match(r"(\d+)(s|ms|us)", time_str.strip())

    if not match:
        raise ValueError(f"Invalid time string: {time_str}")

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "s":
        return value
    elif unit == "ms":
        return value * 1e-3
    elif unit == "us":
        return value * 1e-6


def can_support_panic_count(cmd_list: List[str]):
    """
    Check if the boot params support the panic count feature

    For example: '-device pvpanic-pci', '-qmp unix:/tmp/qmp.sock,server=off,wait=no',
    '-action shutdown=pause,panic=none' and '-s' can support the feature
    """
    found_pvpanic = (
        "pvpanic-pci" in cmd_list and "shutdown=pause,panic=none" in cmd_list
    )

    found_gdb = "-gdb" in cmd_list or "-s" in cmd_list

    found_qmp = False
    for cmd in cmd_list:
        if "mode=control" in cmd or "-qmp" in cmd:
            found_qmp = True

    is_valid = found_qmp and found_gdb and found_pvpanic

    return is_valid


def panic_count(socket_client: SocketClient, job_id: int):
    # Add timeout mechanism to avoid infinite loop
    max_attempts = 30  # Try up to 30 times, about 60 seconds
    for attempt in range(max_attempts):
        if socket_client.connect():
            break
        time.sleep(2)
        if attempt == max_attempts - 1:
            socket_client.logger.error(
                "Failed to connect to socket after multiple attempts"
            )
            return  # Exit function if connection fails

    socket_client.send('{"execute": "qmp_capabilities"}')

    # Create a new thread to run listen with timeout
    listen_thread = threading.Thread(target=socket_client.listen)
    listen_thread.daemon = True
    listen_thread.start()

    # Give listen thread at most 5 minutes to run
    listen_thread.join(300)

    # logger has already released here after socket_client disconnected to QEMU
    # store the results to file
    os.makedirs("/tmp/" + str(job_id), exist_ok=True)
    with open("/tmp/" + str(job_id) + "/panic_count.txt", "w") as f:
        f.write(str(socket_client.panic))
        f.flush()
    del socket_client


def app_inject(socket_client: SocketClient_app):
    try:
        # Use event and timeout mechanism
        completed = threading.Event()

        def listen_with_timeout(socket_client):
            try:
                socket_client.listen()
            except Exception as e:
                socket_client.logger.error(f"Exception in listen thread: {e}")
            finally:
                completed.set()  # Mark task as completed

        # Start a thread to execute listen operation
        listen_thread = threading.Thread(
            target=listen_with_timeout,
            args=[
                socket_client,
            ],
        )
        listen_thread.daemon = True
        listen_thread.start()

        # Wait for at most 5 minutes
        if not completed.wait(300):
            socket_client.logger.warning("App inject timeout after 300 seconds")

    except Exception as e:
        socket_client.logger.error(f"Error in app_inject: {str(e)}")
    finally:
        del socket_client


def parse_json_objects(buffer):
    """
    Parse multiple JSON objects from buffer (backward compatibility wrapper).

    :param buffer: String buffer containing JSON data
    :return: Tuple of (list of parsed objects, remaining buffer)
    """
    return QMPMonitor._parse_json_buffer(buffer)


# FIXME: implement a QEMU protocol to monitor VM boots
