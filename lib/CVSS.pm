package CVSS;

use feature ':5.10';
use strict;
use utf8;
use warnings;

use Carp     ();
use Exporter qw(import);

use constant DEBUG => $ENV{CVSS_DEBUG};

use CVSS::v2;
use CVSS::v3;
use CVSS::v4;

our @EXPORT = qw(encode_cvss decode_cvss cvss_to_xml);

our $VERSION = '0.99';
$VERSION =~ tr/_//d;    ## no critic

my $CVSS_CLASSES = {'2.0' => 'CVSS::v2', '3.0' => 'CVSS::v3', '3.1' => 'CVSS::v3', '4.0' => 'CVSS::v4'};

sub encode_cvss { __PACKAGE__->new(@_)->to_string }
sub decode_cvss { __PACKAGE__->from_vector_string(shift) }

sub cvss_to_xml { @_ > 1 ? __PACKAGE__->new(@_)->to_xml : __PACKAGE__->from_vector_string(shift)->to_xml }

sub new {

    my ($class, %params) = @_;
    Carp::croak 'Missing CVSS version' unless $params{version};

    my $cvss_class = $CVSS_CLASSES->{$params{version}} or Carp::croak 'Unknown CVSS version';
    return $cvss_class->new(%params);

}

sub from_vector_string {

    my ($class, $vector_string) = @_;

    my %metrics    = split /[\/:]/, $vector_string;
    my $version    = delete $metrics{CVSS} || '2.0';
    my $cvss_class = $CVSS_CLASSES->{$version} or Carp::croak 'Unknown CVSS version';

    DEBUG and say STDERR "-- CVSS v$version -- Vector String: $vector_string";
    return $cvss_class->new(version => sprintf('%.1f', $version), metrics => \%metrics,
        vector_string => $vector_string);

}

1;

__END__
=head1 NAME

CVSS - Perl extension for CVSS (Common Vulnerability Scoring System) 2.0/3.x/4.0

=head1 SYNOPSIS

  use CVSS;

  # OO-interface

  # Method 1 - Use params

  $cvss = CVSS->new(
    version => '3.1',
    metrics => {
        AV => 'A',
        AC => 'L',
        PR => 'L',
        UI => 'R',
        S => 'U',
        C => 'H',
        I => 'H',
        A => 'H',
    }
  );


  # Method 2 - Decode and parse the vector string

  $cvss = CVSS->from_vector_string('CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H');


  # Method 3 - Builder

  use CVSS 

  $cvss = CVSS->new(version => '3.1');
  $cvss->attack_vector('ADJACENT_NETWORK');
  $cvss->attack_complexity('LOW');
  $cvss->privileges_required('LOW');
  $cvss->user_interaction('REQUIRED');
  $cvss->scope('UNCHANGED');
  $cvss->confidentiality_impact('HIGH');
  $cvss->integrity_impact('HIGH');
  $cvss->availability_impact('HIGH');

  $cvss->calculate_score;


  # Convert the CVSS object in "vector string"
  say $cvss; # CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H

  # Get metric value
  say $cvss->AV; # A
  say $cvss->attack_vector; # ADJACENT_NETWORK

  # Get the base score
  say $cvss->base_score; # 7.4

  # Get the base severity
  say $cvss->base_severity # HIGH

  # Parse the CVSS "vector string"
  $cvss = CVSS->from_vector_string('CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H');


  # exported functions

  use CVSS qw(decode_cvss encode_cvss)

  $cvss = decode_cvss('CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H');
  say $cvss->base_score;  # 7.4

  $vector_string = encode_cvss(version => '3.1', metrics => {...});
  say $cvss_string; # CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H


=head1 DESCRIPTION

This module calculates the CVSS (Common Vulnerability Scoring System) scores
(basic, temporal, and environmental), convert the "vector string" and returns
the L<CVSS> object in JSON or XML.

The Common Vulnerability Scoring System (CVSS) provides a way to capture the
principal characteristics of a vulnerability and produce a numerical score
reflecting its severity. The numerical score can then be translated into a
qualitative representation (such as low, medium, high, and critical) to help
organizations properly assess and prioritize their vulnerability management
processes.

L<https://www.first.org/cvss/>


=head2 FUNCTIONAL INTERFACE

They are exported by default:

=over

=item $vector_string = encode_cvss(%params)

Converts the given CVSS params to "vector string". Croaks on error.

This function call is functionally identical to:

    $vector_string = CVSS->new(%params)->to_string;

=item $cvss = decode_cvss($vector_string)

Converts the given "vector string" to L<CVSS>. Croaks on error.

This function call is functionally identical to:

    $cvss = CVSS->from_vector_string($vector_string);

=back

=head2 OBJECT-ORIENTED INTERFACE

=over

=item $cvss = CVSS->new(%params)

Creates a new L<CVSS> instance using the provided parameters (B<version>, B<metric>
or B<vector_string>) and returns the CVSS subclass that matches the selected CVSS
version (C<2.0>, C<3.0>, C<3.1> or C<4.0>):

  +--------------+----------+
  | CVSS version | Class    |
  +--------------+----------+
  | 2.0          | CVSS::v2 |
  | 3.0          | CVSS::v3 |
  | 3.1          | CVSS::v3 |
  | 4.0          | CVSS::v4 |
  +--------------+----------+

=item $cvss = CVSS->from_vector_string($vector_string);

Converts the given "vector string" to L<CVSS>. Croaks on error

=back

=head3 Common methods

=over

=item $cvss->base_score

Return the base score (0 - 10).

=item $cvss->base_severity

Return the base severity (LOW, MEDIUM, HIGH or CRITICAL).

=item $cvss->temporal_score

Return the temporal score (0 - 10).

=item $cvss->temporal_severity

Return the temporal severity (LOW, MEDIUM, HIGH or CRITICAL).

=item $cvss->environmental_score

Return the environmental score (0 - 10).

=item $cvss->environmental_severity

Return the environmental severity (LOW, MEDIUM, HIGH or CRITICAL).

=item $cvss->to_xml

Convert the L<CVSS> object in XML in according of CVSS XML Schema Definition.

=item $cvss->calculate_score

Performs the calculation of the score in accordance with the CVSS specification.

=over

=item * https://nvd.nist.gov/schema/cvss-v2_0.2.xsd - XSD for CVSS v2.0

=item * https://www.first.org/cvss/cvss-v3.0.xsd - XSD for CVSS v3.0

=item * https://www.first.org/cvss/cvss-v3.1.xsd - XSD for CVSS v3.1

=item * https://www.first.org/cvss/cvss-v4.0.xsd - XSD for CVSS v4.0

=back

    say $cvss->to_xml;

    # <?xml version="1.0" encoding="UTF-8"?>
    # <cvssv3.1 xmlns="https://www.first.org/cvss/cvss-v3.1.xsd"
    #   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    #   xsi:schemaLocation="https://www.first.org/cvss/cvss-v3.1.xsd https://www.first.org/cvss/cvss-v3.1.xsd"
    #   >
    # 
    #   <base_metrics>
    #     <attack-vector>ADJACENT_NETWORK</attack-vector>
    #     <attack-complexity>LOW</attack-complexity>
    #     <privileges-required>LOW</privileges-required>
    #     <user-interaction>REQUIRED</user-interaction>
    #     <scope>UNCHANGED</scope>
    #     <confidentiality-impact>HIGH</confidentiality-impact>
    #     <integrity-impact>HIGH</integrity-impact>
    #     <availability-impact>HIGH</availability-impact>
    #     <base-score>7.4</base-score>
    #     <base-severity>HIGH</base-severity>
    #   </base_metrics>
    # 
    # </cvssv3.1>

=item $cvss->TO_JSON

Helper method for JSON modules (L<JSON>, L<JSON::PP>, L<JSON::XS>, L<Mojo::JSON>, etc).

Convert the L<CVSS> object in JSON format in according of CVSS JSON Schema.

=over

=item * https://www.first.org/cvss/cvss-v2.0.json - JSON Schema for CVSS v2.0.

=item * https://www.first.org/cvss/cvss-v3.0.json - JSON Schema for CVSS v3.0.

=item * https://www.first.org/cvss/cvss-v3.1.json - JSON Schema for CVSS v3.1.

=item * https://www.first.org/cvss/cvss-v4.0.json - JSON Schema for CVSS v4.0.

=back

    use Mojo::JSON qw(encode_json);

    say encode_json($cvss);

    # {
    #    "attackComplexity" : "LOW",
    #    "attackVector" : "ADJACENT_NETWORK",
    #    "availabilityImpact" : "HIGH",
    #    "baseScore" : 7.4,
    #    "baseSeverity" : "HIGH",
    #    "confidentialityImpact" : "HIGH",
    #    "integrityImpact" : "HIGH",
    #    "privilegesRequired" : "LOW",
    #    "scope" : "UNCHANGED",
    #    "userInteraction" : "REQUIRED",
    #    "vectorString" : "CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
    #    "version" : "3.1"
    # }

=back


=head1 SEE ALSO

L<CVSS::v2>, L<CVSS::v3>, L<CVSS::v4>

=over 4

=item [FIRST] CVSS Data Representations (L<https://www.first.org/cvss/data-representations>)

=item [FIRST] CVSS v4.0 Specification (L<https://www.first.org/cvss/v4.0/specification-document>)

=item [FIRST] CVSS v3.1 Specification (L<https://www.first.org/cvss/v3.1/specification-document>)

=item [FIRST] CVSS v3.0 Specification (L<https://www.first.org/cvss/v3.0/specification-document>)

=item [FIRST] CVSS v2.0 Complete Guide (L<https://www.first.org/cvss/v2/guide>)

=back


=head1 SUPPORT

=head2 Bugs / Feature Requests

Please report any bugs or feature requests through the issue tracker
at L<https://github.com/giterlizzi/perl-CVSS/issues>.
You will be notified automatically of any progress on your issue.

=head2 Source Code

This is open source software.  The code repository is available for
public review and contribution under the terms of the license.

L<https://github.com/giterlizzi/perl-CVSS>

    git clone https://github.com/giterlizzi/perl-CVSS.git


=head1 AUTHOR

=over 4

=item * Giuseppe Di Terlizzi <gdt@cpan.org>

=back


=head1 LICENSE AND COPYRIGHT

This software is copyright (c) 2023-2024 by Giuseppe Di Terlizzi.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut
