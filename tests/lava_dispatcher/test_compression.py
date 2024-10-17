# Copyright (C) 2018 Linaro Limited
#
# Author: Matt Hart <matthew.hart@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import responses
from responses import RequestsMock

from lava_common.exceptions import InfrastructureError, JobError
from lava_dispatcher.actions.deploy.download import HttpDownloadAction
from lava_dispatcher.utils.compression import decompress_command_map, decompress_file
from tests.lava_dispatcher.test_basic import Factory, LavaDispatcherTestCase


def setup_responses() -> RequestsMock:
    download_artifacts_dir = Path(__file__).parent / "download_artifacts"
    requests_mock = RequestsMock(assert_all_requests_are_fired=True)

    for compression_postfix in ("gz", "xz", "zip", "bz2"):
        compression_file_path = download_artifacts_dir / f"10MB.{compression_postfix}"
        compression_file_contents = compression_file_path.read_bytes()
        download_url = (
            "http://example.com/functional-test-images/"
            f"compression/10MB.{compression_postfix}"
        )
        requests_mock.add(
            responses.GET,
            url=download_url,
            body=compression_file_contents,
        )

    return requests_mock


class TestDecompression(LavaDispatcherTestCase):
    def setUp(self):
        super().setUp()
        self.factory = Factory()
        self.requests_mock = setup_responses()
        self.requests_mock.start()

    def tearDown(self):
        self.requests_mock.stop()
        self.requests_mock.reset()

    def test_download_decompression(self):
        job = self.factory.create_kvm_job("sample_jobs/compression.yaml")
        job.validate()

        self.assertEqual(len(job.pipeline.describe()), 2)

        http_download_actions = job.pipeline.find_all_actions(HttpDownloadAction)
        self.assertEqual(len(http_download_actions), 4)

        sha256sum = "31e00e0e4c233c89051cd748122fde2c98db0121ca09ba93a3820817ea037bc5"
        md5sum = "596c35b949baf46b721744a13f76a258"
        shazipsum = "27259c7aab942273931b71d1fa37e0c5115b6b0fcc969ee40c2e6bb1062af98f"
        md5zipsum = "ec769af027b3dd8145b75369bfb2698b"
        filesize = 10240000
        zipsize = 10109

        for httpaction in http_download_actions:
            httpaction.validate()
            httpaction.parameters = httpaction.parameters["images"]
            httpaction.run(None, None)
            output = httpaction.get_namespace_data(
                action="download-action", label=httpaction.key, key="file"
            )
            outputfile = output.split("/")[-1]
            sha256hash = hashlib.sha256()
            md5sumhash = hashlib.md5()  # nosec - not used for cryptography
            with open(output, "rb", buffering=0) as f:
                for b in iter(lambda: f.read(128 * 1024), b""):
                    sha256hash.update(b)
                    md5sumhash.update(b)
            outputmd5 = md5sumhash.hexdigest()
            outputsha = sha256hash.hexdigest()
            outputsize = os.path.getsize(os.path.join(httpaction.path, output))
            self.assertIsInstance(httpaction.size, int)
            # enforce_content_length handles size integrity
            self.assertEqual(httpaction.size, -1)
            if httpaction.key == "testzip":
                # zipfiles are NOT decompressed on the fly
                self.assertEqual(outputmd5, md5zipsum)
                self.assertEqual(outputsha, shazipsum)
                self.assertEqual(outputsize, zipsize)
                # zipfiles aren't decompressed, so shouldn't change name
                self.assertEqual(outputfile, "10MB.zip")
                # enforce_content_length handles size integrity
                self.assertEqual(httpaction.size, -1)
            else:
                self.assertEqual(outputmd5, md5sum)
                self.assertEqual(outputsha, sha256sum)
                self.assertEqual(outputsize, filesize)
                self.assertEqual(outputfile, "10MB")

    def test_bad_download_decompression(self):
        job = self.factory.create_kvm_job("sample_jobs/compression_bad.yaml")
        job.validate()

        http_download_actions = job.pipeline.find_all_actions(HttpDownloadAction)

        tests_dict = {action.key: action for action in http_download_actions}
        test_bad_sha256sum = tests_dict["test_bad_sha256sum"]
        test_xz_bad_format = tests_dict["test_xz_bad_format"]
        test_gz_bad_format = tests_dict["test_gz_bad_format"]
        test_bz2_bad_format = tests_dict["test_bz2_bad_format"]
        test_multiple_bad_checksums = tests_dict["test_multiple_bad_checksums"]

        with self.subTest("Test bad sha256sum"), self.assertRaisesRegex(
            JobError, "does not match"
        ):
            test_bad_sha256sum.validate()
            test_bad_sha256sum.run(None, None)

        with self.subTest("Test bad XZ format"), self.assertRaisesRegex(
            JobError, "subprocess exited with non-zero code"
        ):
            test_xz_bad_format.validate()
            test_xz_bad_format.run(None, None)

        with self.subTest("Test bad GZ format"), self.assertRaisesRegex(
            JobError, "subprocess exited with non-zero code"
        ):
            test_gz_bad_format.validate()
            test_gz_bad_format.run(None, None)

        with self.subTest("Test bad BZ2 format"), self.assertRaisesRegex(
            JobError, "subprocess exited with non-zero code"
        ):
            test_bz2_bad_format.validate()
            test_bz2_bad_format.run(None, None)

        with self.subTest("Test multiple bad checksums"), self.assertRaisesRegex(
            JobError, "md5.*does not match"
        ):
            test_multiple_bad_checksums.validate()
            test_multiple_bad_checksums.run(None, None)


class TestDownloadDecompressionMap(LavaDispatcherTestCase):
    def test_download_decompression_map(self):
        """
        Previously had an issue with decompress_command_map being modified.
        This should be a constant. If this is modified during calling decompress_file
        then a regression has occurred.
        :return:
        """
        # Take a complete copy of decompress_command_map before it has been modified
        copy_of_command_map = copy.deepcopy(decompress_command_map)
        # Call decompress_file, we only need it to create the command required,
        # it doesn't need to complete successfully.
        with self.assertRaises(InfrastructureError):
            with TemporaryDirectory() as temp_dir:
                decompress_file(f"{temp_dir}/test", "zip")  # nosec - unit test only.
        self.assertEqual(copy_of_command_map, decompress_command_map)
