#!perl

use strict;
use warnings;

use Test::More;

use_ok('CVSS');
use_ok('CVSS::v2');
use_ok('CVSS::v3');

done_testing();

diag("CVSS $CVSS::VERSION, Perl $], $^X");
