#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_kle");

plan skip_all => "kle provider is disabled" if disabled("kle");

simple_test("test_kle", "kle_test");
