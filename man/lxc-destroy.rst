:orphan:

Description
###########

Summary
*******

Mocks ``lxc-destroy`` command used by Linaro Automated Validation Architecture
(LAVA). LXC is Linux Containers userspace tools. ``lxc-destroy`` does not
use LXC. It is part of ``lava-lxc-mocker``, which mocks some of the LXC
commands used by LAVA.

SYNOPSIS
********

lxc-destroy {-n name}

Options
*******

  -n NAME             Use container identifier NAME. The container identifier
                      format is an alphanumeric string. It removes the
                      directory /var/lib/lxc/NAME

``lxc-destroy`` accepts the above option. Any other option specified other than
the above, will be ignored.

Examples
********

To mock destroy a container, use
  lxc-destroy -n container

NOTE
****
The commands provided by ``lava-lxc-mocker`` are simple shell scripts that use
the same command names mocking some LXC commands and does not
use LXC. ``lava-lxc-mocker`` commands still need to be executed in the same
sequence as a typical LXC operation. In particular, once a container has been
created, that container needs to be destroyed to clean up the symlinks and
other artifacts.

See Also
********
lava-lxc-mocker(7), lxc-attach(1), lxc-create(1), lxc-device(1), lxc-info(1),
lxc-start(1), lxc-stop(1)

License
*******
Released under the MIT License:
http://www.opensource.org/licenses/mit-license.php
