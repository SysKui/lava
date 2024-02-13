# Copyright (C) 2024 Collabora Limited
#
# Author: Igor Ponomarev <igor.ponomarev@collabora.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
from rest_framework.routers import DefaultRouter

from .testjob import TestJobViewset

router = DefaultRouter()

router.register(r"jobs", TestJobViewset)
