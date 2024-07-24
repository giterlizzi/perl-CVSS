package CVSS::Base;

use feature ':5.10';
use strict;
use utf8;
use warnings;

use Carp;
use POSIX qw(floor round);

our $VERSION = '0.99';
$VERSION =~ tr/_//d;    ## no critic

use overload '""' => \&to_string, fallback => 1;

use constant DEBUG => $ENV{CVSS_DEBUG};

sub new {

    my ($class, %params) = @_;

    Carp::croak 'Missing CVSS version' unless $params{version};

    $params{metrics}       //= {};
    $params{scores}        //= {};
    $params{vector_string} //= undef;

    my $self = bless {%params}, $class;

    if (!$self->version =~ /(2.0|3.[0-1]|4.0)/) {
        Carp::croak 'Invalid CVSS version';
    }

    if ($self->{vector_string}) {

        DEBUG and say STDERR sprintf('-- Validate vector string: %s', $self->VECTOR_STRING_REGEX);

        if ($self->{vector_string} !~ $self->VECTOR_STRING_REGEX) {
            Carp::croak 'Invalid CVSS vector string';
        }

        $self->calculate_score;

    }

    return $self;

}

sub from_vector_string {

    my ($class, $vector_string) = @_;

    my %metrics = split /[\/:]/, $vector_string;
    my $version = delete $metrics{CVSS} || '2.0';

    DEBUG and say STDERR "-- Vector String: $vector_string";
    return $class->new(version => $version, metrics => \%metrics, vector_string => $vector_string);

}

sub SEVERITY            { {} }
sub NOT_DEFINED_VALUE   { }
sub VECTOR_STRING_REGEX {qw{}}
sub METRIC_GROUPS       { {} }
sub METRIC_NAMES        { {} }


sub _metric_name_to_value {
    my ($self, $metric, $name) = @_;
    $name =~ s/\s/_/g;
    $self->metrics->{$metric} = $self->METRIC_NAMES->{$metric}->{names}->{$name};
    return $self;
}

sub _metric_value_to_name {
    my ($self, $metric) = @_;
    $self->METRIC_NAMES->{$metric}->{values}->{$self->metrics->{$metric}};
}

sub version       { shift->{version} }
sub vector_string { $_[0]->{vector_string} || $_[0]->to_vector_string }
sub metrics       { shift->{metrics} }
sub scores        { shift->{scores} }

sub base_score    { shift->{base_score} }
sub base_severity { $_[0]->score_to_severity($_[0]->base_score) }

# Only for CVSS 2.0 and 3.x
sub temporal_score    { shift->{temporal_score} }
sub temporal_severity { $_[0]->score_to_severity($_[0]->temporal_score) }

# Only for CVSS 2.0 and 3.x
sub environmental_score    { shift->{environmental_score} }
sub environmental_severity { $_[0]->score_to_severity($_[0]->environmental_score) }

sub metric_group_is_set {

    my ($self, $type) = @_;

    for (@{$self->METRIC_GROUPS->{$type}}) {
        return 1 if ($self->M($_) && $self->M($_) ne $self->NOT_DEFINED_VALUE);
    }

}

sub metric_is_not_defined { ($_[0]->metric($_[1]) eq $_[0]->NOT_DEFINED_VALUE) }

sub metric {
    my ($self, $metric) = @_;
    my $value = $self->M($metric);

    return $self->METRIC_NAMES->{$metric}->{values}->{$value};
}

sub M { $_[0]->metrics->{$_[1]} }

sub score_to_severity {

    my ($self, $score) = @_;

    return unless (!!$score);

    my $SEVERITY = $self->SEVERITY;

    foreach (keys %{$SEVERITY}) {
        my $range = $SEVERITY->{$_};
        if ($score >= $range->{min} && $score <= $range->{max}) {
            return $_;
        }
    }

    Carp::croak 'Unknown severity';

}

sub calculate_score { Carp::croak sprintf('%s->calculate_score() is not implemented in subclass', ref(shift)) }

sub to_xml { Carp::croak sprintf('%s->to_xml() is not implemented in subclass', ref(shift)) }

sub to_string { shift->to_vector_string }

sub to_vector_string {

    my ($self) = @_;

    my $metrics = $self->metrics;
    my @vectors = ();

    if ($self->version > 2.0) {
        push @vectors, sprintf('CVSS:%s', $self->version);
    }

    foreach my $metric (@{$self->METRIC_GROUPS->{base}}) {
        push @vectors, sprintf('%s:%s', $metric, $metrics->{$metric});
    }

    foreach my $metric ((
        @{$self->METRIC_GROUPS->{threat}},        @{$self->METRIC_GROUPS->{temporal}},
        @{$self->METRIC_GROUPS->{environmental}}, @{$self->METRIC_GROUPS->{supplemental}}
    ))
    {
        if (defined $metrics->{$metric} && $metrics->{$metric} ne $self->NOT_DEFINED_VALUE) {
            push @vectors, sprintf('%s:%s', $metric, $metrics->{$metric});
        }
    }

    return join '/', @vectors;

}

sub TO_JSON {

    my ($self) = @_;

    # Required in CVSS == v2.0: version, vectorString and baseScore
    # Required in CVSS >= v3.0: version, vectorString, baseScore and baseSeverity

    $self->calculate_score unless ($self->base_score);

    my $json = {
        version      => sprintf('%.1f', $self->version),
        vectorString => $self->vector_string,
        baseScore    => $self->base_score
    };

    if ($self->version > 2.0) {
        $json->{baseSeverity} = $self->base_severity;
    }

    my $metrics = $self->metrics;

    foreach my $metric (@{$self->METRIC_GROUPS->{base}}) {
        $json->{$self->METRIC_NAMES->{$metric}->{json}}
            = $self->METRIC_NAMES->{$metric}->{values}->{$metrics->{$metric}};
    }

    foreach my $metric ((
        @{$self->METRIC_GROUPS->{threat}},        @{$self->METRIC_GROUPS->{temporal}},
        @{$self->METRIC_GROUPS->{environmental}}, @{$self->METRIC_GROUPS->{supplemental}}
    ))
    {
        if ($metrics->{$metric} && $metrics->{$metric} ne $self->NOT_DEFINED_VALUE) {
            $json->{$self->METRIC_NAMES->{$metric}->{json}}
                = $self->METRIC_NAMES->{$metric}->{values}->{$metrics->{$metric}};
        }
    }

    if ($self->version <= 3.1) {

        if ($self->metric_group_is_set('temporal')) {

            $json->{temporalScore} = $self->temporal_score;

            if ($self->version != 2.0) {
                $json->{temporalSeverity} = $self->temporal_severity;
            }

        }

        if ($self->metric_group_is_set('environmental')) {

            $json->{environmentalScore} = $self->environmental_score;

            if ($self->version != 2.0) {
                $json->{environmentalSeverity} = $self->environmental_severity;
            }

        }

    }

    # CVSS 4.0

    # environmentalScore
    # environmentalSeverity
    # threatScore
    # threatSeverity

    return $json;

}

1;
__END__

=pod

=head1 NAME

CVSS::Base - Base class for CVSS

=head1 DESCRIPTION

These are base class for internal CVSS use.

=head1 SEE ALSO

L<CVSS>

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
