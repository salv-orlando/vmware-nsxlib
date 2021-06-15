# Copyright 2020 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from collections import namedtuple
import logging
import traceback

import six
from urllib3.exceptions import MaxRetryError
from urllib3.exceptions import ResponseError
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

RequestHistory = namedtuple(
    "RequestHistory", ["method", "url", "error", "status", "redirect_location"]
)


class RetryDebug(Retry):
    """Class that adds debugging capabilities of Retry"""
    def __init__(self, *args, **kw):
        super(RetryDebug, self).__init__(*args, **kw)

    def increment(self, method=None, url=None, response=None, error=None,
                  _pool=None, _stacktrace=None, ):
        log.debug("Retry Increment %s", traceback.format_stack())
        if self.total is False and error:
            # Disabled, indicate to re-raise the error.
            raise six.reraise(type(error), error, _stacktrace)

        total = self.total
        if total is not None:
            total -= 1

        connect = self.connect
        read = self.read
        redirect = self.redirect
        status_count = self.status
        cause = "unknown"
        status = None
        redirect_location = None

        if error and self._is_connection_error(error):
            # Connect retry?
            if connect is False:
                raise six.reraise(type(error), error, _stacktrace)
            elif connect is not None:
                connect -= 1

        elif error and self._is_read_error(error):
            # Read retry?
            if read is False or not self._is_method_retryable(method):
                raise six.reraise(type(error), error, _stacktrace)
            elif read is not None:
                read -= 1

        elif response and response.get_redirect_location():
            # Redirect retry?
            if redirect is not None:
                redirect -= 1
            cause = "too many redirects"
            redirect_location = response.get_redirect_location()
            status = response.status

        else:
            # Incrementing because of a server error like a 500 in
            # status_forcelist and a the given method is in the whitelist
            cause = ResponseError.GENERIC_ERROR
            if response and response.status:
                if status_count is not None:
                    status_count -= 1
                cause = ResponseError.SPECIFIC_ERROR.format(
                    status_code=response.status)
                status = response.status

        history = self.history + (
            RequestHistory(method, url, error, status, redirect_location),
        )

        new_retry = self.new(
            total=total,
            connect=connect,
            read=read,
            redirect=redirect,
            status=status_count,
            history=history,
        )

        if new_retry.is_exhausted():
            raise MaxRetryError(_pool, url, error or ResponseError(cause))

        # log the cause for this retry
        log.debug("Cause for retry: %s", cause)
        # log the server response for this retry
        log.debug("Response: %s", response)
        log.debug("Incremented Retry for (url='%s'): %r", url, new_retry)

        return new_retry
