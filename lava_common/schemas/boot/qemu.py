#
# Copyright (C) 2018 Linaro Limited
#
# Author: Rémi Duraffort <remi.duraffort@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later

from voluptuous import All, Msg, Optional, Required

from lava_common.schemas import boot, docker


def qemu_docker():
    return {**docker(), Optional("binary"): str}


def qemu_fault_inject():
    return {
        Required("commands"): list,
        Required("stdout"): str,
        Required("stderr"): str,
        Optional("delayed"): str,
        Optional("qmp_socket"): str,
        Optional("socket_app"):str,
        Optional("start_command"):str,
        Optional("port"): str,
        Optional("host"): str,
        Optional("guest_send_path"): str,
        Optional("inject_after_boot"): bool,
        Optional("ssh_port"): int,
        Optional("ssh_host"): str,
    }


def schema():
    base = {
        Required("method"): Msg("qemu", "'method' should be 'qemu'"),
        Optional("connection"): "serial",  # FIXME: is this needed or required?
        Optional("media"): "tmpfs",
        Optional("prompts"): boot.prompts(),
        Optional("transfer_overlay"): boot.transfer_overlay(),
        Optional(
            "auto_login"
        ): boot.auto_login(),  # TODO: if auto_login => prompt is required
        Optional("docker"): qemu_docker(),
        Optional("fault_inject_params"): qemu_fault_inject(),
    }
    return {**boot.schema(), **base}
