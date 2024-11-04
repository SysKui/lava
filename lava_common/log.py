# Copyright (C) 2014 Linaro Limited
#
# Author: Senthil Kumaran S <senthil.kumaran@linaro.org>
#         Remi Duraffort <remi.duraffort@linaro.org>
#
# SPDX-License-Identifier: GPL-2.0-or-later
from __future__ import annotations

import contextlib
import datetime
import logging
import multiprocessing
import os
import signal
import sys
import time

import requests

from lava_common.version import __version__
from lava_common.yaml import yaml_safe_dump


def dump(data: dict) -> str:
    # Set width to a really large value in order to always get one line.
    # But keep this reasonable because the logs will be loaded by CLoader
    # that is limited to around 10**7 chars
    data_str = yaml_safe_dump(
        data, default_flow_style=True, default_style='"', width=10**5
    )[:-1]
    # Test the limit and skip if the line is too long
    if len(data_str) >= 10**5:
        if isinstance(data["msg"], str):
            data["msg"] = "<line way too long ...>"
        else:
            data["msg"] = {"skip": "line way too long ..."}
        data_str = yaml_safe_dump(
            data, default_flow_style=True, default_style='"', width=10**6
        )[:-1]
    return data_str


class JobOutputSender:
    FAILURE_SLEEP = 5

    def __init__(
        self,
        conn: multiprocessing.connection.Connection,
        url: str,
        token: str,
        max_time: int,
    ):
        self.conn = conn
        self.url = url
        self.token = token
        self.max_time = max_time
        self.max_records = 1000

        self.headers = {"User-Agent": f"lava {__version__}", "LAVA-Token": token}
        self.session = requests.Session()
        # Record the exception to prevent spamming
        self.last_exception_type: type[Exception] | None = None
        self.exception_counter = 0

        self.records: list[str] = []
        self.index = 0

    def read_and_send_records(self) -> None:
        last_call = time.monotonic()
        leaving = False
        while not leaving:
            # Listen for new messages if we don't have message yet or some
            # messages are already in the socket.
            if len(self.records) == 0 or self.conn.poll(self.max_time):
                data = self.conn.recv_bytes()
                if data == b"":
                    leaving = True
                else:
                    self.records.append(data.decode("utf-8", errors="replace"))

            records_limit = len(self.records) >= self.max_records
            time_limit = (time.monotonic() - last_call) >= self.max_time
            if self.records and (records_limit or time_limit):
                last_call = time.monotonic()
                # Send the data
                self.post()

    def run(self) -> None:
        with self.session:
            self.read_and_send_records()

            # Flush remaining records
            while self.records:
                # Send the data
                self.post()

    def post(self) -> None:
        # limit the number of records to send in one call
        records_to_send = self.records[: self.max_records]
        with contextlib.suppress(requests.RequestException):
            # Do not specify a timeout so we wait forever for an answer. This is a
            # background process so waiting is not an issue.
            # Will avoid resending the same request a second time if gunicorn
            # is too slow to answer.
            # In case of exception, print the exception to stderr that will be
            # forwarded to lava-server by lava-worker. If the same exception is
            # raised multiple time in a row, record also the number of
            # occurrences.
            try:
                ret = self.session.post(
                    self.url,
                    data={
                        "lines": "- " + "\n- ".join(records_to_send),
                        "index": self.index,
                    },
                    headers=self.headers,
                )
                if self.exception_counter > 0:
                    now = datetime.datetime.utcnow().isoformat()
                    sys.stderr.write(f"{now}: <{self.exception_counter} skipped>\n")
                    self.last_exception_type = None
                    self.exception_counter = 0
            except Exception as exc:
                if self.last_exception_type == type(exc):
                    self.exception_counter += 1
                else:
                    now = datetime.datetime.utcnow().isoformat()
                    if self.exception_counter:
                        sys.stderr.write(f"{now}: <{self.exception_counter} skipped>\n")
                    sys.stderr.write(f"{now}: {str(exc)}\n")
                    self.last_exception_type = type(exc)
                    self.exception_counter = 0
                    sys.stderr.flush()

                # Empty response for the rest of the code
                ret = requests.models.Response()

            if ret.status_code == 200:
                with contextlib.suppress(KeyError, ValueError):
                    count = int(ret.json()["line_count"])
                    # Discard records that were successfully sent
                    self.records[0:count] = []
                    self.index += count
            elif ret.status_code == 404:
                self.records[:] = []
                os.kill(os.getppid(), signal.SIGTERM)
            elif ret.status_code == 413:
                self._reduce_record_size()
            else:
                # If the request fails, give some time for the server to
                # recover from the failure.
                time.sleep(self.FAILURE_SLEEP)

    def _reduce_record_size(self) -> None:
        """
        The method should only be called for handling 413 HTTP error code. It
        minus 100 records for every call. In case only one record left, the record will
        be replaced by a short "log-upload fail" result line and an error message also
        will be sent to kill the job.
        """
        if self.max_records == 1:
            record = self.records[0]
            self.records[:] = [
                dump(
                    {
                        "dt": datetime.datetime.utcnow().isoformat(),
                        "lvl": "results",
                        "msg": {
                            "definition": "lava",
                            "case": "log-upload",
                            "result": "fail",
                        },
                    }
                )
            ]

            sys.stderr.write(
                "Error: Log post request body exceeds server settings param.\n"
                f"Log line length: {len(record)}\n"
                f"Truncated log line: {record[:1024]} ...\n"
            )
            sys.stderr.flush()
        else:
            self.max_records = max(1, self.max_records - 100)


def run_output_sender(
    conn: multiprocessing.connection.Connection,
    url: str,
    token: str,
    max_time: int,
) -> None:
    JobOutputSender(
        conn=conn,
        url=url,
        token=token,
        max_time=max_time,
    ).run()


class HTTPHandler(logging.Handler):
    def __init__(self, url, token, interval):
        super().__init__()
        self.formatter = logging.Formatter("%(message)s")
        # Create the multiprocess sender
        (reader, writer) = multiprocessing.Pipe(duplex=False)
        self.writer = writer
        # Block sigint so the sender function will not receive it.
        # TODO: block more signals?
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGINT])
        self.proc = multiprocessing.Process(
            target=run_output_sender, args=(reader, url, token, interval)
        )
        self.proc.start()
        signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT])

    def emit(self, record):
        data = self.formatter.format(record)
        # Skip empty strings
        # This can't happen as data is a dictionary dumped in yaml format
        if data == "":
            return
        self.writer.send_bytes(data.encode("utf-8", errors="replace"))

    def close(self):
        super().close()

        # wait for the multiprocess
        self.writer.send_bytes(b"")
        self.proc.join()


class YAMLLogger(logging.Logger):
    def __init__(self, name):
        super().__init__(name)
        self.handler = None
        self.markers = {}
        self.line = 0

    def addHTTPHandler(self, url, token, interval):
        self.handler = HTTPHandler(url, token, interval)
        self.addHandler(self.handler)
        return self.handler

    def close(self):
        if self.handler is not None:
            self.handler.close()
            self.removeHandler(self.handler)
            self.handler = None

    def log_message(self, level, level_name, message, *args, **kwargs):
        # Increment the line count
        self.line += 1
        # Build the dictionary
        data = {"dt": datetime.datetime.utcnow().isoformat(), "lvl": level_name}

        if isinstance(message, str) and args:
            data["msg"] = message % args
        else:
            data["msg"] = message

        if level_name == "feedback" and "namespace" in kwargs:
            data["ns"] = kwargs["namespace"]

        data_str = dump(data)
        self._log(level, data_str, ())

    def exception(self, exc, *args, **kwargs):
        self.log_message(logging.ERROR, "exception", exc, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        self.log_message(logging.ERROR, "error", message, *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        self.log_message(logging.WARNING, "warning", message, *args, **kwargs)

    def info(self, message, *args, **kwargs):
        self.log_message(logging.INFO, "info", message, *args, **kwargs)

    def debug(self, message, *args, **kwargs):
        self.log_message(logging.DEBUG, "debug", message, *args, **kwargs)

    def input(self, message, *args, **kwargs):
        self.log_message(logging.INFO, "input", message, *args, **kwargs)

    def target(self, message, *args, **kwargs):
        self.log_message(logging.INFO, "target", message, *args, **kwargs)

    def feedback(self, message, *args, **kwargs):
        self.log_message(logging.INFO, "feedback", message, *args, **kwargs)

    def event(self, message, *args, **kwargs):
        self.log_message(logging.INFO, "event", message, *args, **kwargs)

    def marker(self, message, *args, **kwargs):
        case = message["case"]
        m_type = message["type"]
        self.markers.setdefault(case, {})[m_type] = self.line - 1

    def results(self, results, *args, **kwargs):
        if "extra" in results and "level" not in results:
            raise Exception("'level' is mandatory when 'extra' is used")

        # Extract and append test case markers
        case = results["case"]
        markers = self.markers.get(case)
        if markers is not None:
            test_case = markers.get("test_case")
            results["starttc"] = markers.get("start_test_case", test_case)
            results["endtc"] = markers.get("end_test_case", test_case)
            del self.markers[case]

        self.log_message(logging.INFO, "results", results, *args, **kwargs)
