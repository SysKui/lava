# Copyright (C) 2014 Linaro Limited
#
# Author: Neil Williams <neil.williams@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
from __future__ import annotations

import os
import shlex
import subprocess
import shutil
import threading
import re
import json
import socket
from pathlib import Path
from typing import TYPE_CHECKING

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


class TimerWithCallback():
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
        self.timer.start()

    def _run(self):
        """run the callback function"""
        self.callback(*self.args, **self.kwargs)

    def cancel(self):
        """cancel the timer"""
        if self.timer is not None:
            self.timer.cancel()

class SocketClient:
    def __init__(self, server_address):
        """:param server_address: socket file path"""
        # store qemu panic count
        self.panic = 0

        # unix domain sockets 
        self.server_address = server_address
        socket_family = socket.AF_UNIX
        socket_type = socket.SOCK_STREAM

        self.sock = socket.socket(socket_family, socket_type)
        try:
            self.sock.connect(self.server_address)
        except Exception as e:
            raise e
        
    def send(self, data: str):
        """Send str to socket server"""
        self.sock.sendall(data.encode())
    
    def listen(self):
        """Listen the socket server and get the response"""
        while True:
            data = self.sock.recv(1024)
            if not data:
                break
            datajs = json.loads(data)
            if datajs.get("event", "") == "GUEST_PANICKED":
                self.panic += 1
    
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
        rootfs_url = self.job.parameters['actions'][0]['deploy']['images']['rootfs']['url']

        fault_inject = self.job.parameters['actions'][1]['boot'].get('fault_inject', {})
        inject_command = fault_inject.get('commands', [])
        log_stdout = fault_inject.get('stdout', "/dev/null")
        log_stderr = fault_inject.get('stderr', "/dev/null")
        delayed = fault_inject.get('delayed', "")
        socket_file = fault_inject.get('socket', "")
        flipshell = []

        # Are there inject_commands?
        if inject_command != []:
            # Yes, parse inject_command 

            # construct flipshell to inject faults 
            if not Path("/root/flipgdb/fliputils.py").exists():
                self.logger.debug("/root/flipgdb/fliputils.py not exist")
            elif shutil.which("gdb-multiarch") == None:
                self.logger.debug("Executable gdb-multiarch is not found")
            else:
                flipshell.extend([
                    "gdb-multiarch",
                    "-q",
                    "-batch",
                    "-ex","set pagination off",
                    "-ex","target remote:1234",
                    "-ex","maintenance packet Qqemu.PhyMemMode:1",
                    "-ex","source /root/flipgdb/fliputils.py",
                ])
                for cmd in inject_command:
                    if cmd.strip().startswith("snapinject") and not rootfs_url.endswith("qcow2"):
                        self.logger.error("Image type is not qcow2")
                    else:
                        flipshell.extend(["-ex", cmd])
            
            # create a client connected to qemu qmp server to read the panic event and count it
            cmd_list = " ".join(self.sub_command).split(" ")
            kernel_file = cmd_list[cmd_list.index('-kernel') + 1]
            if subprocess.run(['sh', '/root/check-pvpanic', kernel_file]).returncode != 0:
                # kernel should open pvpanic_pci and pvpanic config,
                # because driver pvpanic-pci is necessary to get panic event in qemu
                self.logger.error("pvpanic_pci and pvpanic config not set")
            elif '-qmp' not in cmd_list or 'pvpanic-pci' not in cmd_list or 'shutdown=pause,panic=none' not in cmd_list:
                # qemu boot option is not correct, we need '-device pvpanic-pci', '-qmp unix:/tmp/qmp.sock,server=off,wait=no', '-action shutdown=pause,panic=none'
                self.logger.error('Qemu boot options do not support panic count.')
            else:
                try:
                    socket_client = SocketClient(socket_file)
                    threading.Thread(target=panic_count, args=(socket_client, self.logger)).start()
                except Exception as e:
                    self.logger.error("Count panic got exception: %s", str(e))
        
            if delayed != "":
                timer = TimerWithCallback(parse_time_string(delayed), fault_inject_callback, flipshell, log_stdout, log_stderr, self.logger)
                timer.start()
            else:
                fault_inject_callback(flipshell, log_stdout, log_stderr, self.logger)

        self.set_namespace_data(
            action="shared", label="shared", key="connection", value=shell_connection
        )
        return shell_connection

    def cleanup(self, connection):
        if self.docker is not None:
            self.logger.info("Stopping the qemu container %s", self.docker.__name__)
            self.docker.destroy()

def fault_inject_callback(flipshell, log_stdout, log_stderr, logger):
    with open(log_stdout, "w") as stdout, open(log_stderr, "w") as stderr:
        subprocess.Popen(flipshell, stdout=stdout, stderr=stderr)
    logger.debug("Spawn a thread to inject faults, Command is %s", flipshell)

def parse_time_string(time_str):
    """
    Parse time string to second float number
    
    :param time_str: time string, like '1s', '2ms', '3us'
    :return: second float number
    """
    
    match = re.match(r'(\d+)(s|ms|us)', time_str.strip())
    
    if not match:
        raise ValueError(f"Invalid time string: {time_str}")
    
    value = int(match.group(1))  
    unit = match.group(2)        

    if unit == 's':
        return value  
    elif unit == 'ms':
        return value * 1e-3  
    elif unit == 'us':
        return value * 1e-6 

def panic_count(socket_client: SocketClient, logger):
    socket_client.send('{"execute": "qmp_capabilities"}')
    socket_client.listen()
    logger.debug(f'panic count: {socket_client.panic}')
    logger.results(
        {
            "definition": "panic count",
            "case": "panic count",
            "result": str(socket_client.panic),
        }
    )
    del socket_client


# FIXME: implement a QEMU protocol to monitor VM boots
