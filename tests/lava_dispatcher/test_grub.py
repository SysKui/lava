# Copyright (C) 2016 Linaro Limited
#
# Author: Matthew Hart <matthew.hart@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later


import unittest
from unittest.mock import patch

from lava_common.exceptions import JobError
from lava_common.yaml import yaml_safe_load
from lava_dispatcher.action import Pipeline
from lava_dispatcher.actions.boot import (
    AutoLoginAction,
    BootloaderCommandOverlay,
    BootloaderInterruptAction,
)
from lava_dispatcher.actions.boot.grub import (
    GrubMainAction,
    GrubMenuSelector,
    GrubSequenceAction,
)
from lava_dispatcher.actions.boot.secondary import SecondaryShellAction
from lava_dispatcher.actions.boot.uefi_menu import UEFIMenuInterrupt
from lava_dispatcher.actions.deploy.apply_overlay import (
    ExtractNfsRootfs,
    PrepareOverlayTftp,
)
from lava_dispatcher.actions.deploy.fastboot import FastbootFlashAction
from lava_dispatcher.actions.deploy.tftp import TftpAction
from lava_dispatcher.actions.test.shell import TestShellRetry
from lava_dispatcher.connections.serial import ConnectShell
from lava_dispatcher.device import NewDevice
from lava_dispatcher.utils import filesystem
from lava_dispatcher.utils.network import dispatcher_ip
from lava_dispatcher.utils.strings import substitute
from tests.lava_dispatcher.test_basic import Factory, LavaDispatcherTestCase
from tests.utils import infrastructure_error, infrastructure_error_multi_paths


class GrubFactory(Factory):
    """
    Not Model based, this is not a Django factory.
    Factory objects are dispatcher based classes, independent
    of any database objects.
    """

    def create_mustang_job(self, filename):
        return self.create_job("mustang1.jinja2", filename)

    def create_hikey_job(self, filename):
        return self.create_job("hi6220-hikey-r2-01.jinja2", filename)

    def create_hikey960_job(self, filename):
        return self.create_job("hi960-hikey-01.jinja2", filename)


class TestGrubAction(LavaDispatcherTestCase):
    def setUp(self):
        super().setUp()
        self.factory = GrubFactory()

    @unittest.skipIf(infrastructure_error("mkimage"), "u-boot-tools not installed")
    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_simulated_action(self, which_mock):
        job = self.factory.create_job("d02-01.jinja2", "sample_jobs/grub-ramdisk.yaml")
        self.assertIsNotNone(job)

        # uboot and uboot-ramdisk have the same pipeline structure
        description_ref = self.pipeline_reference("grub.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())

        self.assertIsNone(job.validate())

    def test_tftp_pipeline(self):
        job = self.factory.create_job("d02-01.jinja2", "sample_jobs/grub-ramdisk.yaml")
        self.assertEqual(
            [action.name for action in job.pipeline.actions],
            ["tftp-deploy", "grub-main-action", "lava-test-retry", "finalize"],
        )
        tftp = job.pipeline.find_action(TftpAction)
        self.assertTrue(
            tftp.get_namespace_data(action=tftp.name, label="tftp", key="ramdisk")
        )
        self.assertIsNotNone(tftp.pipeline)
        self.assertEqual(
            [action.name for action in tftp.pipeline.actions],
            [
                "download-retry",
                "download-retry",
                "download-retry",
                "prepare-tftp-overlay",
                "lxc-create-udev-rule-action",
                "deploy-device-env",
            ],
        )
        self.assertIn(
            "ramdisk",
            [action.key for action in tftp.pipeline.actions if hasattr(action, "key")],
        )
        self.assertIn(
            "kernel",
            [action.key for action in tftp.pipeline.actions if hasattr(action, "key")],
        )
        self.assertIn(
            "dtb",
            [action.key for action in tftp.pipeline.actions if hasattr(action, "key")],
        )
        self.assertNotIn("=", filesystem.tftpd_dir())

    def test_device_d02(self):
        job = self.factory.create_job("d02-01.jinja2", "sample_jobs/grub-ramdisk.yaml")
        self.assertNotIn("connect", job.device["commands"])
        self.assertEqual(
            job.device["commands"]["connections"]["uart0"]["connect"],
            "telnet ratchet 7003",
        )
        self.assertEqual(job.device["commands"].get("interrupt", " "), " ")
        methods = job.device["actions"]["boot"]["methods"]
        self.assertIn("grub", methods)
        self.assertEqual(
            methods["grub"]["parameters"].get("bootloader_prompt"), "grub>"
        )

    @unittest.skipIf(infrastructure_error("mkimage"), "u-boot-tools not installed")
    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_grub_action(self, which_mock):
        job = self.factory.create_job("d02-01.jinja2", "sample_jobs/grub-ramdisk.yaml")
        job.validate()
        self.assertEqual(job.pipeline.errors, [])
        self.assertIn("grub", job.device["actions"]["boot"]["methods"])
        params = job.device["actions"]["boot"]["methods"]["grub"]["parameters"]
        boot_message = params.get(
            "boot_message", job.device.get_constant("kernel-start-message")
        )
        self.assertIsNotNone(boot_message)
        for action in job.pipeline.actions:
            action.validate()
            if isinstance(action, GrubMainAction):
                self.assertIn("method", action.parameters)
                self.assertEqual("grub", action.parameters["method"])
            if isinstance(action, TftpAction):
                self.assertIn("ramdisk", action.parameters)
                self.assertIn("kernel", action.parameters)
                self.assertIn("to", action.parameters)
                self.assertEqual("tftp", action.parameters["to"])
            if isinstance(action, BootloaderInterruptAction):
                self.assertFalse(action.interrupt_newline)
            self.assertTrue(action.valid)

    def test_overlay_action(self):
        parameters = {
            "device_type": "d02",
            "job_name": "grub-standard-ramdisk",
            "job_timeout": "15m",
            "action_timeout": "5m",
            "priority": "medium",
            "actions": {
                "boot": {
                    "method": "grub",
                    "commands": "ramdisk",
                    "prompts": ["linaro-test", "root@debian:~#"],
                },
                "deploy": {
                    "ramdisk": "initrd.gz",
                    "kernel": "zImage",
                    "dtb": "broken.dtb",
                },
            },
        }
        (rendered, _) = self.factory.create_device("d02-01.jinja2")
        device = NewDevice(yaml_safe_load(rendered))
        job = self.create_simple_job(
            device_dict=device,
            job_parameters=parameters,
        )
        pipeline = Pipeline(job=job, parameters=parameters["actions"]["boot"])
        job.pipeline = pipeline
        overlay = BootloaderCommandOverlay(job)
        pipeline.add_action(overlay)
        ip_addr = dispatcher_ip(None)
        parsed = []
        kernel = parameters["actions"]["deploy"]["kernel"]
        ramdisk = parameters["actions"]["deploy"]["ramdisk"]
        dtb = parameters["actions"]["deploy"]["dtb"]

        substitution_dictionary = {
            "{SERVER_IP}": ip_addr,
            # the addresses need to be hexadecimal
            "{RAMDISK}": ramdisk,
            "{KERNEL}": kernel,
            "{DTB}": dtb,
        }
        params = device["actions"]["boot"]["methods"]
        commands = params["grub"]["ramdisk"]["commands"]
        self.assertIn("net_bootp", commands)
        self.assertIn(
            "linux (tftp,{SERVER_IP})/{KERNEL} console=ttyS0,115200 earlycon=uart8250,mmio32,0x80300000 root=/dev/ram0 ip=dhcp",
            commands,
        )
        self.assertIn("initrd (tftp,{SERVER_IP})/{RAMDISK}", commands)
        self.assertIn("devicetree (tftp,{SERVER_IP})/{DTB}", commands)

        params["grub"]["ramdisk"]["commands"] = substitute(
            params["grub"]["ramdisk"]["commands"], substitution_dictionary
        )
        substituted_commands = params["grub"]["ramdisk"]["commands"]
        self.assertIs(type(substituted_commands), list)
        self.assertIn("net_bootp", substituted_commands)
        self.assertNotIn(
            "linux (tftp,{SERVER_IP})/{KERNEL} console=ttyS0,115200 earlycon=uart8250,mmio32,0x80300000 root=/dev/ram0 ip=dhcp",
            substituted_commands,
        )
        self.assertIn(
            "linux (tftp,%s)/%s console=ttyS0,115200 earlycon=uart8250,mmio32,0x80300000 root=/dev/ram0 ip=dhcp"
            % (ip_addr, kernel),
            substituted_commands,
        )
        self.assertNotIn("initrd (tftp,{SERVER_IP})/{RAMDISK}", parsed)
        self.assertNotIn("devicetree (tftp,{SERVER_IP})/{DTB}", parsed)

    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_download_action(self, which_mock):
        job = self.factory.create_job("d02-01.jinja2", "sample_jobs/grub-nfs.yaml")
        for action in job.pipeline.actions:
            action.validate()
            if not action.valid:
                raise JobError(action.errors)
            self.assertTrue(action.valid)
        job.validate()
        self.assertEqual(job.pipeline.errors, [])

        overlay = job.pipeline.find_action(PrepareOverlayTftp)
        extract = overlay.pipeline.find_action(ExtractNfsRootfs)
        test_dir = overlay.get_namespace_data(
            action="test", label="results", key="lava_test_results_dir"
        )
        self.assertIsNotNone(test_dir)
        self.assertIn("/lava-", test_dir)
        self.assertIsNotNone(extract)
        self.assertEqual(extract.timeout.duration, 600)

    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_reset_actions(self, which_mock):
        job = self.factory.create_job("d02-01.jinja2", "sample_jobs/grub-ramdisk.yaml")
        for action in job.pipeline.actions:
            action.validate()
            self.assertTrue(action.valid)

        grub_action = job.pipeline.find_action(GrubMainAction)
        names = [r_action.name for r_action in grub_action.pipeline.actions]
        self.assertIn("connect-device", names)
        self.assertIn("reset-device", names)
        self.assertIn("bootloader-interrupt", names)
        self.assertIn("expect-shell-connection", names)
        self.assertIn("bootloader-commands", names)

    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_grub_with_monitor(self, which_mock):
        job = self.factory.create_job(
            "d02-01.jinja2", "sample_jobs/grub-ramdisk-monitor.yaml"
        )
        job.validate()
        description_ref = self.pipeline_reference("grub-ramdisk-monitor.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())

    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_grub_via_efi(self, which_mock):
        job = self.factory.create_mustang_job("sample_jobs/mustang-grub-efi-nfs.yaml")
        self.assertIsNotNone(job)
        job.validate()
        description_ref = self.pipeline_reference("mustang-grub-efi-nfs.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())

        menu = job.pipeline.find_action(UEFIMenuInterrupt)
        self.assertIn("item_class", menu.params)

        grub_efi = job.pipeline.find_action(GrubMenuSelector)
        self.assertEqual("pxe-grub", grub_efi.commands)

    @unittest.skipIf(infrastructure_error("lxc-start"), "lxc-start not installed")
    def test_hikey_grub_efi(self):
        job = self.factory.create_hikey_job("sample_jobs/hikey-grub-lxc.yaml")
        self.assertIsNotNone(job)
        job.validate()
        description_ref = self.pipeline_reference("hikey-grub-efi.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())

    @unittest.skipIf(
        infrastructure_error_multi_paths(["lxc-info", "img2simg", "simg2img"]),
        "lxc or img2simg or simg2img not installed",
    )
    def test_hikey_uart(self):
        job = self.factory.create_hikey_job("sample_jobs/hikey-console.yaml")
        self.assertIsNotNone(job)
        job.validate()
        description_ref = self.pipeline_reference("hikey-console.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())

        command = job.pipeline.find_action(ConnectShell)
        self.assertEqual("isolation", command.parameters["namespace"])
        self.assertEqual("uart0", command.hardware)
        self.assertIn("connections", job.device["commands"])
        uart = job.device["commands"]["connections"][command.hardware]["connect"]
        self.assertIn(command.command, uart)
        self.assertEqual("telnet localhost 4002", uart)

        tshells = job.pipeline.find_all_actions(TestShellRetry)
        for shell in tshells:
            cn = shell.parameters.get("connection-namespace")
            if cn:
                self.assertEqual(shell.parameters["namespace"], "hikey-oe")
                self.assertNotEqual(shell.parameters["namespace"], "isolation")
                self.assertNotEqual(shell.parameters["namespace"], "tlxc")
                self.assertEqual(shell.parameters["connection-namespace"], "isolation")
                retry = [action for action in shell.pipeline.actions][0]
                self.assertEqual(retry.parameters["connection-namespace"], "isolation")
            else:
                self.assertNotEqual(shell.parameters["namespace"], "hikey-oe")
                self.assertNotEqual(shell.parameters["namespace"], "isolation")
                self.assertEqual(shell.parameters["namespace"], "tlxc")
                self.assertNotIn("connection-namespace", shell.parameters.keys())

        grub_menu = job.pipeline.find_action(GrubSequenceAction)
        grub_autologin = grub_menu.pipeline.find_action(AutoLoginAction)
        self.assertIsNone(grub_autologin.params)
        self.assertEqual(["login:"], grub_autologin.parameters.get("prompts"))

        secondary_menu = job.pipeline.find_action(SecondaryShellAction)
        secondary_autologin = secondary_menu.pipeline.find_action(AutoLoginAction)
        self.assertIsNotNone(secondary_autologin.parameters)
        self.assertIn("isolation", secondary_autologin.job.test_info)
        self.assertIn("hikey-oe", secondary_autologin.job.test_info)
        self.assertIn("tlxc", secondary_autologin.job.test_info)

    @unittest.skipIf(infrastructure_error("lxc-start"), "lxc-start not installed")
    def test_hikey960_grub(self):
        job = self.factory.create_hikey960_job("sample_jobs/hikey960-oe.yaml")
        self.assertIsNotNone(job)
        job.validate()
        description_ref = self.pipeline_reference("hi960-grub-efi.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())

        flash = job.pipeline.find_action(FastbootFlashAction)
        self.assertIsNotNone(flash.interrupt_prompt)
        self.assertEqual("Android Fastboot mode", flash.interrupt_prompt)
        self.assertIsNotNone(flash.interrupt_string)
        self.assertEqual(" ", flash.interrupt_string)

        login = job.pipeline.find_action(AutoLoginAction)
        self.assertIsNotNone(login)

    @patch(
        "lava_dispatcher.actions.deploy.tftp.which", return_value="/usr/bin/in.tftpd"
    )
    def test_synquacer_grub(self, which_mock):
        job = self.factory.create_job(
            "synquacer-dtb-01.jinja2", "sample_jobs/synquacer-dtb.yaml"
        )
        self.assertIsNotNone(job)
        job.validate()
        description_ref = self.pipeline_reference("synquacer_dtb.yaml", job=job)
        self.assertEqual(description_ref, job.pipeline.describe())
