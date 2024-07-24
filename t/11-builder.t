#!perl

use v5.10;
use Test::More;

use CVSS::v3;

my $base_score    = 7.4;
my $vector_string = 'CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H';

my $cvss = CVSS::v3->new(version => '3.1');

$cvss->attack_vector('ADJACENT_NETWORK');
$cvss->attack_complexity('LOW');
$cvss->privileges_required('LOW');
$cvss->user_interaction('REQUIRED');
$cvss->scope('UNCHANGED');
$cvss->confidentiality_impact('HIGH');
$cvss->integrity_impact('HIGH');
$cvss->availability_impact('HIGH');

$cvss->calculate_score();

cmp_ok($cvss->base_score,       '==', $base_score,    "Check base score ($base_score)");
cmp_ok($cvss->to_vector_string, 'eq', $vector_string, "Check vector string ($vector_string)");

cmp_ok($cvss->attack_vector,          'eq', 'ADJACENT_NETWORK', 'Check attack_vector value');
cmp_ok($cvss->attack_complexity,      'eq', 'LOW',              'Check attack_complexity value');
cmp_ok($cvss->privileges_required,    'eq', 'LOW',              'Check privileges_required value');
cmp_ok($cvss->user_interaction,       'eq', 'REQUIRED',         'Check user_interaction value');
cmp_ok($cvss->scope,                  'eq', 'UNCHANGED',        'Check scope value');
cmp_ok($cvss->confidentiality_impact, 'eq', 'HIGH',             'Check confidentiality_impact value');
cmp_ok($cvss->integrity_impact,       'eq', 'HIGH',             'Check integrity_impact value');
cmp_ok($cvss->availability_impact,    'eq', 'HIGH',             'Check availability_impact value');

cmp_ok($cvss->M('AV'), 'eq', 'A', 'Check AV metric value');
cmp_ok($cvss->M('AC'), 'eq', 'L', 'Check AC metric value');
cmp_ok($cvss->M('PR'), 'eq', 'L', 'Check PR metric value');
cmp_ok($cvss->M('UI'), 'eq', 'R', 'Check UI metric value');
cmp_ok($cvss->M('S'),  'eq', 'U', 'Check S metric value');
cmp_ok($cvss->M('C'),  'eq', 'H', 'Check C metric value');
cmp_ok($cvss->M('I'),  'eq', 'H', 'Check I metric value');
cmp_ok($cvss->M('A'),  'eq', 'H', 'Check A metric value');

done_testing();
