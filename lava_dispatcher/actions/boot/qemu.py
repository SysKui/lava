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


class TimerWithCallback:
    def __init__(self, interval, callback, *args, **kwargs):
        """
        :param interval: timer interval
        :param callback: callback function
        :param args: function args
        :param kwargs: function args
        """
        self.interval = interval
        self.callback = callback
        self.args = args
        self.kwargs = kwargs
        self.timer = None

    def start(self):
        """Start the timer"""
        self.timer = threading.Timer(self.interval, self._run)
        self.timer.daemon = True
        self.timer.start()

    def _run(self):
        """run the callback function"""
        self.callback(*self.args, **self.kwargs)

    def cancel(self):
        """cancel the timer"""
        if self.timer is not None:
            self.timer.cancel()


class SocketClient:
    def __init__(self, server_address, logger, shell):
        """
        :param server_address: socket file path
        :param logger: lava logger
        :param shell: pexcept.spawn shell
        """
        # store qemu panic count
        self.panic = 0

        # store pexcept.spawn class to interact with qemu
        self.shell = shell

        # set lava logger
        self.logger = logger

        # unix domain sockets
        self.server_address = server_address
        socket_family = socket.AF_UNIX
        socket_type = socket.SOCK_STREAM

        self.sock = socket.socket(socket_family, socket_type)

    def connect(self):
        try:
            self.logger.info(f"SocketClient init: Try connect to {self.server_address}")
            self.sock.connect(self.server_address)
            self.logger.info(f"SocketClient connect to {self.server_address}")
        except Exception as e:
            self.logger.error(f"SocketClient init error: {e}")
            return False
        return True

    def send(self, data: str):
        """Send str to socket server"""
        self.sock.sendall(data.encode())

    def listen(self):
        """Listen the socket server and get the response"""

        buffer = ""
        # Set socket timeout to avoid infinite blocking on recv
        self.sock.settimeout(5)
        # Set a total timeout period, listen for maximum 5 minutes
        max_listen_time = 300  # 5 minutes
        start_time = time.time()

        try:
            while time.time() - start_time < max_listen_time:
                try:
                    data = self.sock.recv(1024)
                    if not data:  # If connection closed, received data will be empty
                        self.logger.debug("Connection closed by remote")
                        break

                    # there maybe more than one object in data. one object per line.
                    # use parse function to parse the json objects
                    buffer += data.decode()
                    results, buffer = parse_json_objects(buffer)
                    for res in results:
                        if res.get("event", "") == "GUEST_PANICKED":
                            self.panic += 1
                            self.logger.debug("qemu panic! panic count: %d", self.panic)
                            # send enter to qemu when it restore to match pexpect prompt
                            self.shell.send("\r")
                            self.logger.debug("Already sended enter to qemu")
                except socket.timeout:
                    # On timeout, just continue the loop until total timeout
                    continue
                except Exception as e:
                    self.logger.error(f"Error in socket listen: {str(e)}")
                    break
        finally:
            self.logger.debug(f"Listen ended with panic count: {self.panic}")

    def __del__(self):
        """Clean the socket"""
        self.sock.close()


# Client to inject faults to user's app
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
        :param hots: host for ssh
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
            subprocess.Popen(self.flipshell, stdout=stdout, stderr=stderr)
        self.logger.debug(
            "Spawn a thread to inject faults, Command is %s", self.flipshell
        )

    def listen(self):
        """Listen the socket server and get the response"""

        def is_port_listening(host, port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            try:
                sock.connect((host, port))
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

        max_retries = 3  # Retry at most 2 time (i.e. 3 attempts in total)
        retry_delay = 5  # Retry interval (seconds)

        for attempt in range(max_retries + 1):
            try:
                ssh = pexpect.spawn(
                    f"ssh -p {self.port} -o StrictHostKeyChecking=no {self.username}@{self.host}"
                )
                logfile = open("/tmp/sshlogfile.txt", "wb")
                ssh.logfile = logfile
                ssh.expect(f"{self.username}@{self.host}'s password: ", timeout=600)
                ssh.sendline(str(self.password))
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
            ssh.expect(f"{self.username}@{self.host}'s password: ", timeout=600)
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

        # Inject faults into qemu virtual machine
        # Get the file system path
        rootfs_url = self.job.parameters["actions"][0]["deploy"]["images"]["rootfs"][
            "url"
        ]

        fault_inject = self.job.parameters["actions"][1]["boot"].get("fault_inject", {})
        prompts = self.job.parameters["actions"][1]["boot"].get("prompts", [])[0]
        password = (
            self.job.parameters["actions"][1]["boot"]
            .get("auto_login", {})
            .get("password", "519ailab")
        )
        # Returns the injected command, otherwise returns an empty list
        inject_command = fault_inject.get("commands", [])
        # stdout: /tmp/test.out
        log_stdout = fault_inject.get("stdout", "/dev/null")
        # stderr: /tmp/test.err
        log_stderr = fault_inject.get("stderr", "/dev/null")
        # Add a delay option
        delayed = fault_inject.get("delayed", "")
        # socket: /tmp/qmp.sock
        socket_file = fault_inject.get("socket", "")
        # /tmp/vm_sync_signal
        socket_app_file = fault_inject.get("socket_app", "")
        # User startup command
        app_start_command = fault_inject.get("start_command", "")

        flipshell = []

        # Are there inject_commands?
        if inject_command != []:
            # Yes, parse inject_command
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
                # Determine whether appinject is used
                # TODO: Use argparse to parse the param, not parse by the index.
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
                            flipshell.extend(["-ex", cmd + " /root/output.log"])
                        else:
                            flipshell.extend(["-ex", cmd])
                try:
                    os.makedirs("/tmp/" + str(self.job.job_id))
                except FileExistsError:
                    self.logger.error(
                        "Dir /tmp/" + str(self.job.job_id) + "already existed"
                    )
                with open(
                    "/tmp/" + str(self.job.job_id) + "/fault_number.txt", "w"
                ) as f:
                    f.write(str(fault_number))
                # Add detach and quit to make sure qemu continue
                flipshell.extend(["-ex", "detach", "-ex", "quit"])

            # create a client connected to qemu qmp server to read the panic event and count it
            cmd_list = " ".join(self.sub_command).split(" ")
            kernel_file = cmd_list[cmd_list.index("-kernel") + 1]
            if (
                subprocess.run(["sh", "/root/check-pvpanic", kernel_file]).returncode
                != 0
            ):
                # Kernel should open 'ikconfig', 'pvpanic_pci' and 'pvpanic' config,
                # because driver 'pvpanic-pci' is necessary to get panic event in qemu,
                # and 'ikconfig' is necessary to check whether the pvpanic-pci config is chosen
                self.logger.error("pvpanic_pci and pvpanic config not set")

            # TODO: implement a more roburst command checker here.
            elif not can_support_panic_count(cmd_list):
                self.logger.error("Qemu boot options do not support panic count.")
            else:
                try:
                    socket_client = SocketClient(socket_file, self.logger, shell)
                    panic_thread = threading.Thread(
                        target=panic_count, args=(socket_client, self.job.job_id)
                    )
                    panic_thread.daemon = True  # Set as daemon thread so it will terminate when main program exits
                    panic_thread.start()
                    self.logger.debug("panic count thread started")
                except Exception as e:
                    self.logger.error("Count panic got exception: %s", str(e))

            if is_appinject:
                try:
                    socket_client_app = SocketClient_app(
                        socket_app_file,
                        self.logger,
                        app_start_command,
                        flipshell,
                        log_stdout,
                        log_stderr,
                        port=fault_inject.get("port", "1234"),
                        host=fault_inject.get("host", "localhost"),
                        password=password,
                        prompts=prompts,
                        guest_send_path=fault_inject.get(
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
                # Delayed execution of the inject action
                if delayed != "":
                    timer = TimerWithCallback(
                        parse_time_string(delayed),
                        fault_inject_callback,
                        flipshell,
                        log_stdout,
                        log_stderr,
                        self.logger,
                    )
                    timer.start()
                else:
                    fault_inject_callback(
                        flipshell, log_stdout, log_stderr, self.logger
                    )

        self.set_namespace_data(
            action="shared", label="shared", key="connection", value=shell_connection
        )

        return shell_connection

    def cleanup(self, connection):
        if self.docker is not None:
            self.logger.info("Stopping the qemu container %s", self.docker.__name__)
            self.docker.destroy()


def fault_inject_callback(flipshell, log_stdout, log_stderr, logger):
    """
    Use pexpect to start gdb-multiarch and execute commands one by one

    :param flipshell: List of command arguments for gdb-multiarch
    :param log_stdout: Path to stdout log file
    :param log_stderr: Path to stderr log file
    :param logger: Logger instance
    """
    try:
        # Extract gdb binary and commands from flipshell
        if not flipshell or flipshell[0] != "gdb-multiarch":
            logger.error("Invalid flipshell command structure")
            return

        # Parse commands from flipshell list
        gdb_commands = []
        i = 1  # Skip "gdb-multiarch"
        while i < len(flipshell):
            if flipshell[i] == "-ex" and i + 1 < len(flipshell):
                gdb_commands.append(flipshell[i + 1])
                i += 2
            elif flipshell[i] in ["-q", "-batch"]:
                # Skip these flags as we handle them differently with pexpect
                i += 1
            else:
                i += 1

        if not gdb_commands:
            logger.warning("No gdb commands found in flipshell")
            return

        logger.debug("Starting gdb-multiarch with pexpect, commands: %s", gdb_commands)

        # Start gdb-multiarch with pexpect
        with open(log_stdout, "wb") as stdout, open(log_stderr, "wb") as stderr:
            gdb_process = pexpect.spawn("gdb-multiarch", ["-q"])
            gdb_process.logfile = stdout

            # Wait for the (gdb) prompt
            gdb_process.expect(r"\(gdb\)\s*")
            logger.debug("GDB started and ready")

            # Execute each command one by one
            for cmd in gdb_commands:
                logger.debug("Executing GDB command: %s", cmd)
                gdb_process.sendline(cmd)

                # Wait for the (gdb) prompt to ensure command completion
                try:
                    gdb_process.expect(r"\(gdb\)\s*", timeout=30)
                    logger.debug("Command completed: %s", cmd)
                except pexpect.TIMEOUT:
                    logger.warning("Timeout waiting for command completion: %s", cmd)
                    # Continue with next command even if timeout
                except pexpect.EOF:
                    logger.info("GDB process ended after command: %s", cmd)
                    break

            # Ensure gdb exits cleanly if still running
            if gdb_process.isalive():
                logger.debug("Closing GDB process")

                gdb_process.close()

    except Exception as e:
        logger.error("Error in fault injection: %s", str(e))

    logger.debug("Fault injection thread completed, Command was %s", flipshell)


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
    os.makedirs("/tmp" + str(job_id), exist_ok=True)
    with open("/tmp/" + str(job_id) + "/panic_count.txt", "w") as f:
        f.write(str(socket_client.panic))
        f.flush()
    del socket_client


def app_inject(socket_client: SocketClient_app):
    try:
        # Use event and timeout mechanism
        completed = threading.Event()

        def listen_with_timeout():
            try:
                socket_client.listen()
            finally:
                completed.set()  # Mark task as completed

        # Start a thread to execute listen operation
        listen_thread = threading.Thread(target=listen_with_timeout)
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
    results = []
    while buffer:
        try:
            obj, idx = json.JSONDecoder().raw_decode(buffer)
            results.append(obj)
            buffer = buffer[idx:].lstrip()  # remove parsed part
        except json.JSONDecodeError:
            # partial data, receive next time.
            break
    return results, buffer


# FIXME: implement a QEMU protocol to monitor VM boots
