#!perl

use v5.10;
use Test::More;

use CVSS::v2;

while (my $line = <DATA>) {

    chomp($line);

    my ($base_score, $vector_string) = split /\s+/, $line;

    my $cvss = CVSS::v2->from_vector_string($vector_string);

    cmp_ok($cvss->base_score,       '==', $base_score,    "$base_score --> $vector_string");
    cmp_ok($cvss->to_vector_string, 'eq', $vector_string, "$vector_string");

}

done_testing();

__DATA__
0.0 AV:L/AC:L/Au:N/C:N/I:N/A:N
0.0 AV:N/AC:L/Au:N/C:N/I:N/A:N
0.0 AV:N/AC:M/Au:S/C:N/I:N/A:N
0.8 AV:L/AC:H/Au:M/C:P/I:N/A:N
1.0 AV:L/AC:H/Au:S/C:N/I:N/A:P
1.0 AV:L/AC:H/Au:S/C:N/I:P/A:N
1.0 AV:L/AC:H/Au:S/C:P/I:N/A:N
1.2 AV:L/AC:H/Au:N/C:N/I:N/A:P
1.2 AV:L/AC:H/Au:N/C:N/I:P/A:N
1.2 AV:L/AC:H/Au:N/C:P/I:N/A:N
1.3 AV:L/AC:M/Au:M/C:P/I:N/A:N
1.4 AV:A/AC:H/Au:S/C:N/I:N/A:P
1.4 AV:A/AC:H/Au:S/C:P/I:N/A:N
1.4 AV:L/AC:L/Au:M/C:N/I:P/A:N
1.4 AV:L/AC:L/Au:M/C:P/I:N/A:N
1.5 AV:L/AC:M/Au:S/C:N/I:N/A:P
1.5 AV:L/AC:M/Au:S/C:N/I:P/A:N
1.5 AV:L/AC:M/Au:S/C:P/I:N/A:N
1.7 AV:L/AC:L/Au:S/C:N/I:N/A:P
1.7 AV:L/AC:L/Au:S/C:N/I:P/A:N
1.7 AV:L/AC:L/Au:S/C:P/I:N/A:N
1.7 AV:N/AC:H/Au:M/C:N/I:N/A:P
1.7 AV:N/AC:H/Au:M/C:N/I:P/A:N
1.7 AV:N/AC:H/Au:M/C:P/I:N/A:N
1.8 AV:A/AC:H/Au:N/C:N/I:N/A:P
1.8 AV:A/AC:H/Au:N/C:N/I:P/A:N
1.8 AV:A/AC:H/Au:N/C:P/I:N/A:N
1.9 AV:L/AC:M/Au:N/C:N/I:N/A:P
1.9 AV:L/AC:M/Au:N/C:N/I:P/A:N
1.9 AV:L/AC:M/Au:N/C:P/I:N/A:N
2.1 AV:L/AC:L/Au:N/C:N/I:N/A:P
2.1 AV:L/AC:L/Au:N/C:N/I:P/A:N
2.1 AV:L/AC:L/Au:N/C:P/I:N/A:N
2.1 AV:N/AC:H/Au:S/C:N/I:N/A:P
2.1 AV:N/AC:H/Au:S/C:N/I:P/A:N
2.1 AV:N/AC:H/Au:S/C:P/I:N/A:N
2.3 AV:A/AC:M/Au:S/C:N/I:N/A:P
2.3 AV:A/AC:M/Au:S/C:N/I:P/A:N
2.3 AV:A/AC:M/Au:S/C:P/I:N/A:N
2.4 AV:L/AC:H/Au:S/C:N/I:P/A:P
2.4 AV:L/AC:H/Au:S/C:P/I:N/A:P
2.4 AV:L/AC:H/Au:S/C:P/I:P/A:N
2.6 AV:L/AC:H/Au:N/C:N/I:P/A:P
2.6 AV:L/AC:H/Au:N/C:P/I:N/A:P
2.6 AV:L/AC:H/Au:N/C:P/I:P/A:N
2.6 AV:N/AC:H/Au:N/C:N/I:N/A:P
2.6 AV:N/AC:H/Au:N/C:N/I:P/A:N
2.6 AV:N/AC:H/Au:N/C:P/I:N/A:N
2.7 AV:A/AC:H/Au:M/C:N/I:P/A:P
2.7 AV:A/AC:L/Au:S/C:N/I:N/A:P
2.7 AV:A/AC:L/Au:S/C:N/I:P/A:N
2.7 AV:A/AC:L/Au:S/C:P/I:N/A:N
2.7 AV:L/AC:M/Au:M/C:N/I:P/A:P
2.8 AV:N/AC:M/Au:M/C:N/I:N/A:P
2.8 AV:N/AC:M/Au:M/C:N/I:P/A:N
2.8 AV:N/AC:M/Au:M/C:P/I:N/A:N
2.9 AV:A/AC:H/Au:S/C:P/I:N/A:P
2.9 AV:A/AC:M/Au:N/C:N/I:N/A:P
2.9 AV:A/AC:M/Au:N/C:N/I:P/A:N
2.9 AV:A/AC:M/Au:N/C:P/I:N/A:N
3.0 AV:L/AC:M/Au:S/C:N/I:P/A:P
3.0 AV:L/AC:M/Au:S/C:P/I:P/A:N
3.2 AV:A/AC:H/Au:N/C:P/I:N/A:P
3.2 AV:A/AC:H/Au:N/C:P/I:P/A:N
3.2 AV:L/AC:L/Au:S/C:N/I:P/A:P
3.2 AV:L/AC:L/Au:S/C:P/I:N/A:P
3.2 AV:L/AC:L/Au:S/C:P/I:P/A:N
3.2 AV:N/AC:H/Au:M/C:P/I:P/A:N
3.3 AV:A/AC:L/Au:N/C:N/I:N/A:P
3.3 AV:A/AC:L/Au:N/C:N/I:P/A:N
3.3 AV:A/AC:L/Au:N/C:P/I:N/A:N
3.3 AV:L/AC:M/Au:N/C:N/I:P/A:P
3.3 AV:L/AC:M/Au:N/C:P/I:N/A:P
3.3 AV:L/AC:M/Au:N/C:P/I:P/A:N
3.3 AV:N/AC:L/Au:M/C:N/I:N/A:P
3.3 AV:N/AC:L/Au:M/C:N/I:P/A:N
3.3 AV:N/AC:L/Au:M/C:P/I:N/A:N
3.4 AV:L/AC:H/Au:M/C:P/I:P/A:P
3.5 AV:L/AC:H/Au:S/C:P/I:P/A:P
3.5 AV:N/AC:M/Au:S/C:N/I:N/A:P
3.5 AV:N/AC:M/Au:S/C:N/I:P/A:N
3.5 AV:N/AC:M/Au:S/C:P/I:N/A:N
3.6 AV:L/AC:L/Au:N/C:N/I:P/A:P
3.6 AV:L/AC:L/Au:N/C:P/I:N/A:P
3.6 AV:L/AC:L/Au:N/C:P/I:P/A:N
3.6 AV:N/AC:H/Au:S/C:N/I:P/A:P
3.6 AV:N/AC:H/Au:S/C:P/I:N/A:P
3.6 AV:N/AC:H/Au:S/C:P/I:P/A:N
3.7 AV:A/AC:H/Au:M/C:P/I:P/A:P
3.7 AV:A/AC:L/Au:M/C:N/I:P/A:P
3.7 AV:L/AC:H/Au:M/C:N/I:N/A:C
3.7 AV:L/AC:H/Au:N/C:P/I:P/A:P
3.8 AV:A/AC:M/Au:S/C:N/I:P/A:P
3.8 AV:A/AC:M/Au:S/C:P/I:N/A:P
3.8 AV:A/AC:M/Au:S/C:P/I:P/A:N
3.8 AV:L/AC:H/Au:S/C:C/I:N/A:N
3.8 AV:L/AC:H/Au:S/C:N/I:C/A:N
3.8 AV:L/AC:H/Au:S/C:N/I:N/A:C
4.0 AV:A/AC:H/Au:S/C:P/I:P/A:P
4.0 AV:L/AC:H/Au:N/C:C/I:N/A:N
4.0 AV:L/AC:H/Au:N/C:N/I:C/A:N
4.0 AV:L/AC:H/Au:N/C:N/I:N/A:C
4.0 AV:N/AC:H/Au:N/C:N/I:P/A:P
4.0 AV:N/AC:H/Au:N/C:P/I:N/A:P
4.0 AV:N/AC:H/Au:N/C:P/I:P/A:N
4.0 AV:N/AC:L/Au:S/C:N/I:N/A:P
4.0 AV:N/AC:L/Au:S/C:N/I:P/A:N
4.0 AV:N/AC:L/Au:S/C:P/I:N/A:N
4.1 AV:A/AC:L/Au:S/C:N/I:P/A:P
4.1 AV:A/AC:L/Au:S/C:P/I:N/A:P
4.1 AV:A/AC:L/Au:S/C:P/I:P/A:N
4.1 AV:L/AC:M/Au:M/C:N/I:N/A:C
4.1 AV:L/AC:M/Au:S/C:P/I:P/A:P
4.3 AV:A/AC:H/Au:N/C:P/I:P/A:P
4.3 AV:A/AC:H/Au:S/C:C/I:N/A:N
4.3 AV:A/AC:H/Au:S/C:N/I:N/A:C
4.3 AV:A/AC:M/Au:N/C:N/I:P/A:P
4.3 AV:A/AC:M/Au:N/C:P/I:N/A:P
4.3 AV:A/AC:M/Au:N/C:P/I:P/A:N
4.3 AV:L/AC:L/Au:M/C:N/I:N/A:C
4.3 AV:L/AC:L/Au:S/C:P/I:P/A:P
4.3 AV:N/AC:H/Au:M/C:P/I:P/A:P
4.3 AV:N/AC:M/Au:M/C:N/I:P/A:P
4.3 AV:N/AC:M/Au:M/C:P/I:P/A:N
4.3 AV:N/AC:M/Au:N/C:N/I:N/A:P
4.3 AV:N/AC:M/Au:N/C:N/I:P/A:N
4.3 AV:N/AC:M/Au:N/C:P/I:N/A:N
4.4 AV:L/AC:M/Au:N/C:P/I:P/A:P
4.4 AV:L/AC:M/Au:S/C:C/I:N/A:N
4.4 AV:L/AC:M/Au:S/C:N/I:N/A:C
4.6 AV:A/AC:H/Au:N/C:N/I:N/A:C
4.6 AV:L/AC:L/Au:N/C:P/I:P/A:P
4.6 AV:L/AC:L/Au:S/C:C/I:N/A:N
4.6 AV:L/AC:L/Au:S/C:N/I:C/A:N
4.6 AV:L/AC:L/Au:S/C:N/I:N/A:C
4.6 AV:N/AC:H/Au:S/C:P/I:P/A:P
4.7 AV:A/AC:L/Au:M/C:P/I:P/A:P
4.7 AV:L/AC:H/Au:N/C:P/I:N/A:C
4.7 AV:L/AC:M/Au:N/C:C/I:N/A:N
4.7 AV:L/AC:M/Au:N/C:N/I:C/A:N
4.7 AV:L/AC:M/Au:N/C:N/I:N/A:C
4.7 AV:N/AC:L/Au:M/C:N/I:P/A:P
4.7 AV:N/AC:L/Au:M/C:P/I:P/A:N
4.8 AV:A/AC:L/Au:N/C:N/I:P/A:P
4.8 AV:A/AC:L/Au:N/C:P/I:N/A:P
4.8 AV:A/AC:L/Au:N/C:P/I:P/A:N
4.9 AV:A/AC:M/Au:S/C:P/I:P/A:P
4.9 AV:L/AC:H/Au:M/C:P/I:P/A:C
4.9 AV:L/AC:L/Au:N/C:C/I:N/A:N
4.9 AV:L/AC:L/Au:N/C:N/I:C/A:N
4.9 AV:L/AC:L/Au:N/C:N/I:N/A:C
4.9 AV:N/AC:H/Au:S/C:C/I:N/A:N
4.9 AV:N/AC:H/Au:S/C:N/I:N/A:C
4.9 AV:N/AC:M/Au:S/C:N/I:P/A:P
4.9 AV:N/AC:M/Au:S/C:P/I:N/A:P
4.9 AV:N/AC:M/Au:S/C:P/I:P/A:N
5.0 AV:A/AC:L/Au:M/C:N/I:N/A:C
5.0 AV:N/AC:L/Au:N/C:N/I:N/A:P
5.0 AV:N/AC:L/Au:N/C:N/I:P/A:N
5.0 AV:N/AC:L/Au:N/C:P/I:N/A:N
5.1 AV:N/AC:H/Au:N/C:P/I:P/A:P
5.2 AV:A/AC:L/Au:S/C:P/I:P/A:P
5.2 AV:A/AC:M/Au:S/C:C/I:N/A:N
5.2 AV:A/AC:M/Au:S/C:N/I:N/A:C
5.2 AV:L/AC:H/Au:N/C:P/I:P/A:C
5.2 AV:L/AC:L/Au:S/C:C/I:N/A:P
5.2 AV:L/AC:L/Au:S/C:N/I:P/A:C
5.3 AV:A/AC:H/Au:N/C:C/I:P/A:N
5.4 AV:A/AC:M/Au:N/C:P/I:P/A:P
5.4 AV:L/AC:M/Au:N/C:C/I:N/A:P
5.4 AV:L/AC:M/Au:N/C:C/I:P/A:N
5.4 AV:L/AC:M/Au:N/C:N/I:P/A:C
5.4 AV:L/AC:M/Au:N/C:P/I:C/A:N
5.4 AV:L/AC:M/Au:N/C:P/I:N/A:C
5.4 AV:N/AC:H/Au:N/C:C/I:N/A:N
5.4 AV:N/AC:H/Au:N/C:N/I:C/A:N
5.4 AV:N/AC:H/Au:N/C:N/I:N/A:C
5.4 AV:N/AC:M/Au:M/C:P/I:P/A:P
5.5 AV:A/AC:H/Au:S/C:P/I:P/A:C
5.5 AV:A/AC:L/Au:S/C:C/I:N/A:N
5.5 AV:A/AC:L/Au:S/C:N/I:N/A:C
5.5 AV:L/AC:H/Au:S/C:C/I:C/A:N
5.5 AV:L/AC:H/Au:S/C:N/I:C/A:C
5.5 AV:L/AC:M/Au:S/C:P/I:P/A:C
5.5 AV:N/AC:L/Au:S/C:N/I:P/A:P
5.5 AV:N/AC:L/Au:S/C:P/I:N/A:P
5.5 AV:N/AC:L/Au:S/C:P/I:P/A:N
5.6 AV:L/AC:H/Au:N/C:C/I:C/A:N
5.6 AV:L/AC:H/Au:N/C:C/I:N/A:C
5.6 AV:L/AC:H/Au:N/C:N/I:C/A:C
5.6 AV:L/AC:L/Au:N/C:C/I:N/A:P
5.6 AV:L/AC:L/Au:N/C:C/I:P/A:N
5.6 AV:L/AC:L/Au:N/C:N/I:P/A:C
5.6 AV:L/AC:L/Au:N/C:P/I:C/A:N
5.6 AV:L/AC:L/Au:N/C:P/I:N/A:C
5.6 AV:N/AC:H/Au:S/C:N/I:P/A:C
5.7 AV:A/AC:M/Au:N/C:C/I:N/A:N
5.7 AV:A/AC:M/Au:N/C:N/I:C/A:N
5.7 AV:A/AC:M/Au:N/C:N/I:N/A:C
5.7 AV:L/AC:L/Au:S/C:P/I:P/A:C
5.7 AV:N/AC:M/Au:M/C:N/I:N/A:C
5.8 AV:A/AC:H/Au:N/C:P/I:P/A:C
5.8 AV:A/AC:L/Au:N/C:P/I:P/A:P
5.8 AV:A/AC:M/Au:S/C:N/I:P/A:C
5.8 AV:A/AC:M/Au:S/C:P/I:N/A:C
5.8 AV:N/AC:L/Au:M/C:P/I:P/A:P
5.8 AV:N/AC:M/Au:N/C:N/I:P/A:P
5.8 AV:N/AC:M/Au:N/C:P/I:N/A:P
5.8 AV:N/AC:M/Au:N/C:P/I:P/A:N
5.9 AV:L/AC:H/Au:M/C:C/I:C/A:C
5.9 AV:L/AC:H/Au:N/C:C/I:C/A:P
5.9 AV:L/AC:M/Au:N/C:C/I:P/A:P
5.9 AV:L/AC:M/Au:N/C:P/I:P/A:C
6.0 AV:L/AC:H/Au:S/C:C/I:C/A:C
6.0 AV:L/AC:M/Au:S/C:C/I:C/A:N
6.0 AV:L/AC:M/Au:S/C:N/I:C/A:C
6.0 AV:N/AC:M/Au:S/C:P/I:P/A:P
6.1 AV:A/AC:L/Au:N/C:C/I:N/A:N
6.1 AV:A/AC:L/Au:N/C:N/I:C/A:N
6.1 AV:A/AC:L/Au:N/C:N/I:N/A:C
6.1 AV:L/AC:L/Au:N/C:C/I:P/A:P
6.1 AV:L/AC:L/Au:N/C:P/I:C/A:P
6.1 AV:L/AC:L/Au:N/C:P/I:P/A:C
6.1 AV:N/AC:H/Au:N/C:C/I:P/A:N
6.1 AV:N/AC:H/Au:N/C:N/I:P/A:C
6.1 AV:N/AC:H/Au:S/C:C/I:P/A:P
6.1 AV:N/AC:H/Au:S/C:P/I:P/A:C
6.1 AV:N/AC:L/Au:M/C:N/I:N/A:C
6.2 AV:A/AC:H/Au:N/C:C/I:N/A:C
6.2 AV:A/AC:L/Au:S/C:N/I:P/A:C
6.2 AV:L/AC:H/Au:N/C:C/I:C/A:C
6.2 AV:L/AC:L/Au:S/C:C/I:C/A:N
6.2 AV:L/AC:L/Au:S/C:N/I:C/A:C
6.3 AV:A/AC:M/Au:S/C:P/I:P/A:C
6.3 AV:L/AC:M/Au:M/C:C/I:C/A:C
6.3 AV:L/AC:M/Au:N/C:C/I:C/A:N
6.3 AV:L/AC:M/Au:N/C:C/I:N/A:C
6.3 AV:L/AC:M/Au:N/C:N/I:C/A:C
6.3 AV:N/AC:M/Au:S/C:C/I:N/A:N
6.3 AV:N/AC:M/Au:S/C:N/I:C/A:N
6.3 AV:N/AC:M/Au:S/C:N/I:N/A:C
6.4 AV:A/AC:M/Au:N/C:N/I:P/A:C
6.4 AV:N/AC:L/Au:N/C:N/I:P/A:P
6.4 AV:N/AC:L/Au:N/C:P/I:N/A:P
6.4 AV:N/AC:L/Au:N/C:P/I:P/A:N
6.5 AV:A/AC:H/Au:S/C:C/I:C/A:C
6.5 AV:L/AC:L/Au:M/C:C/I:C/A:C
6.5 AV:N/AC:L/Au:S/C:P/I:P/A:P
6.6 AV:L/AC:L/Au:N/C:C/I:C/A:N
6.6 AV:L/AC:L/Au:N/C:C/I:N/A:C
6.6 AV:L/AC:L/Au:N/C:N/I:C/A:C
6.6 AV:L/AC:M/Au:N/C:C/I:C/A:P
6.6 AV:L/AC:M/Au:N/C:C/I:P/A:C
6.6 AV:L/AC:M/Au:N/C:P/I:C/A:C
6.6 AV:L/AC:M/Au:S/C:C/I:C/A:C
6.6 AV:N/AC:H/Au:N/C:P/I:P/A:C
6.6 AV:N/AC:H/Au:S/C:C/I:C/A:N
6.6 AV:N/AC:H/Au:S/C:C/I:N/A:C
6.6 AV:N/AC:H/Au:S/C:N/I:C/A:C
6.7 AV:A/AC:L/Au:S/C:C/I:P/A:P
6.7 AV:A/AC:L/Au:S/C:P/I:P/A:C
6.8 AV:A/AC:H/Au:N/C:C/I:C/A:C
6.8 AV:A/AC:L/Au:N/C:N/I:P/A:C
6.8 AV:A/AC:L/Au:N/C:P/I:N/A:C
6.8 AV:L/AC:L/Au:N/C:C/I:C/A:P
6.8 AV:L/AC:L/Au:N/C:C/I:P/A:C
6.8 AV:L/AC:L/Au:N/C:P/I:C/A:C
6.8 AV:L/AC:L/Au:S/C:C/I:C/A:C
6.8 AV:N/AC:H/Au:M/C:C/I:C/A:C
6.8 AV:N/AC:H/Au:S/C:C/I:C/A:P
6.8 AV:N/AC:L/Au:S/C:C/I:N/A:N
6.8 AV:N/AC:L/Au:S/C:N/I:C/A:N
6.8 AV:N/AC:L/Au:S/C:N/I:N/A:C
6.8 AV:N/AC:M/Au:N/C:P/I:P/A:P
6.9 AV:A/AC:M/Au:N/C:C/I:P/A:P
6.9 AV:L/AC:M/Au:N/C:C/I:C/A:C
7.0 AV:N/AC:M/Au:S/C:C/I:P/A:N
7.0 AV:N/AC:M/Au:S/C:N/I:P/A:C
7.0 AV:N/AC:M/Au:S/C:P/I:C/A:N
7.0 AV:N/AC:M/Au:S/C:P/I:N/A:C
7.1 AV:A/AC:L/Au:S/C:C/I:C/A:N
7.1 AV:A/AC:L/Au:S/C:C/I:N/A:C
7.1 AV:N/AC:H/Au:N/C:C/I:C/A:N
7.1 AV:N/AC:H/Au:N/C:C/I:N/A:C
7.1 AV:N/AC:H/Au:N/C:N/I:C/A:C
7.1 AV:N/AC:H/Au:S/C:C/I:C/A:C
7.1 AV:N/AC:M/Au:N/C:C/I:N/A:N
7.1 AV:N/AC:M/Au:N/C:N/I:C/A:N
7.1 AV:N/AC:M/Au:N/C:N/I:N/A:C
7.2 AV:A/AC:L/Au:M/C:C/I:C/A:C
7.2 AV:L/AC:L/Au:N/C:C/I:C/A:C
7.3 AV:A/AC:L/Au:N/C:P/I:P/A:C
7.3 AV:A/AC:M/Au:N/C:C/I:C/A:N
7.3 AV:A/AC:M/Au:N/C:C/I:N/A:C
7.3 AV:A/AC:M/Au:N/C:N/I:C/A:C
7.3 AV:N/AC:H/Au:N/C:C/I:C/A:P
7.3 AV:N/AC:H/Au:N/C:C/I:P/A:C
7.4 AV:A/AC:L/Au:S/C:C/I:C/A:P
7.4 AV:A/AC:M/Au:S/C:C/I:C/A:C
7.5 AV:N/AC:L/Au:N/C:P/I:P/A:P
7.5 AV:N/AC:L/Au:S/C:C/I:N/A:P
7.5 AV:N/AC:L/Au:S/C:C/I:P/A:N
7.5 AV:N/AC:L/Au:S/C:N/I:C/A:P
7.5 AV:N/AC:L/Au:S/C:N/I:P/A:C
7.5 AV:N/AC:L/Au:S/C:P/I:C/A:N
7.5 AV:N/AC:L/Au:S/C:P/I:N/A:C
7.5 AV:N/AC:M/Au:S/C:C/I:P/A:P
7.5 AV:N/AC:M/Au:S/C:P/I:P/A:C
7.6 AV:A/AC:M/Au:N/C:C/I:C/A:P
7.6 AV:A/AC:M/Au:N/C:C/I:P/A:C
7.6 AV:A/AC:M/Au:N/C:P/I:C/A:C
7.6 AV:N/AC:H/Au:N/C:C/I:C/A:C
7.7 AV:A/AC:L/Au:S/C:C/I:C/A:C
7.7 AV:N/AC:L/Au:M/C:C/I:C/A:N
7.8 AV:A/AC:L/Au:N/C:C/I:C/A:N
7.8 AV:A/AC:L/Au:N/C:N/I:C/A:C
7.8 AV:N/AC:L/Au:N/C:C/I:N/A:N
7.8 AV:N/AC:L/Au:N/C:N/I:C/A:N
7.8 AV:N/AC:L/Au:N/C:N/I:N/A:C
7.8 AV:N/AC:M/Au:N/C:C/I:P/A:N
7.8 AV:N/AC:M/Au:N/C:N/I:P/A:C
7.8 AV:N/AC:M/Au:N/C:P/I:C/A:N
7.8 AV:N/AC:M/Au:N/C:P/I:N/A:C
7.9 AV:A/AC:M/Au:N/C:C/I:C/A:C
7.9 AV:N/AC:M/Au:M/C:C/I:C/A:C
7.9 AV:N/AC:M/Au:S/C:C/I:C/A:N
7.9 AV:N/AC:M/Au:S/C:C/I:N/A:C
7.9 AV:N/AC:M/Au:S/C:N/I:C/A:C
8.0 AV:A/AC:L/Au:N/C:C/I:P/A:C
8.0 AV:A/AC:L/Au:N/C:P/I:C/A:C
8.0 AV:N/AC:L/Au:S/C:C/I:P/A:P
8.0 AV:N/AC:L/Au:S/C:P/I:C/A:P
8.0 AV:N/AC:L/Au:S/C:P/I:P/A:C
8.2 AV:N/AC:M/Au:S/C:C/I:C/A:P
8.2 AV:N/AC:M/Au:S/C:P/I:C/A:C
8.3 AV:A/AC:L/Au:N/C:C/I:C/A:C
8.3 AV:N/AC:L/Au:M/C:C/I:C/A:C
8.3 AV:N/AC:M/Au:N/C:C/I:P/A:P
8.3 AV:N/AC:M/Au:N/C:P/I:C/A:P
8.3 AV:N/AC:M/Au:N/C:P/I:P/A:C
8.5 AV:N/AC:L/Au:N/C:C/I:N/A:P
8.5 AV:N/AC:L/Au:N/C:C/I:P/A:N
8.5 AV:N/AC:L/Au:N/C:N/I:C/A:P
8.5 AV:N/AC:L/Au:N/C:N/I:P/A:C
8.5 AV:N/AC:L/Au:N/C:P/I:C/A:N
8.5 AV:N/AC:L/Au:N/C:P/I:N/A:C
8.5 AV:N/AC:L/Au:S/C:C/I:C/A:N
8.5 AV:N/AC:L/Au:S/C:C/I:N/A:C
8.5 AV:N/AC:L/Au:S/C:N/I:C/A:C
8.5 AV:N/AC:M/Au:S/C:C/I:C/A:C
8.7 AV:N/AC:L/Au:S/C:C/I:C/A:P
8.7 AV:N/AC:L/Au:S/C:C/I:P/A:C
8.7 AV:N/AC:L/Au:S/C:P/I:C/A:C
8.8 AV:N/AC:M/Au:N/C:C/I:C/A:N
8.8 AV:N/AC:M/Au:N/C:N/I:C/A:C
9.0 AV:N/AC:L/Au:N/C:C/I:P/A:P
9.0 AV:N/AC:L/Au:N/C:P/I:C/A:P
9.0 AV:N/AC:L/Au:N/C:P/I:P/A:C
9.0 AV:N/AC:L/Au:S/C:C/I:C/A:C
9.0 AV:N/AC:M/Au:N/C:C/I:P/A:C
9.0 AV:N/AC:M/Au:N/C:P/I:C/A:C
9.3 AV:N/AC:M/Au:N/C:C/I:C/A:C
9.4 AV:N/AC:L/Au:N/C:C/I:C/A:N
9.4 AV:N/AC:L/Au:N/C:C/I:N/A:C
9.4 AV:N/AC:L/Au:N/C:N/I:C/A:C
9.7 AV:N/AC:L/Au:N/C:C/I:C/A:P
9.7 AV:N/AC:L/Au:N/C:P/I:C/A:C
10.0 AV:N/AC:L/Au:N/C:C/I:C/A:C