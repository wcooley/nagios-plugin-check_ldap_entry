#!/usr/bin/perl -w
#
# Copyright (C) 2014 Wil Cooley
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#

require 5.004;
use strict;
use English qw(-no_match_vars);
use Nagios::Plugin;
use Net::LDAP;

my $VERSION = '0.1.0';

my $np = Nagios::Plugin->new(
    usage     => 'Usage: %s -H <host_or_URI> -e <entry_filter> '
                    . '-E <nonentry_filter>',
    shortname => 'LDAP Entry',
    version   => $VERSION,
    url       => 'https://github.com/wcooley/nagios-plugin-check_ldap_entry',
    blurb     => 'Check for presence or absence of particular LDAP entries',
);

$np->add_arg(
    spec  => 'host|H=s',
    label => 'HOSTNAME',
    help  => 'Host name or IP address of LDAP server or URI');
$np->add_arg(
    spec  => 'base|b=s',
    label => 'BASE',
    help  => 'LDAP search base DN');
$np->add_arg(
    spec  => 'scope|s=s',
    label => 'base|one|sub|children',
    help  => 'LDAP search scope',
    default => 'sub');
$np->add_arg(
    spec  => 'entry_filter|e=s@',
    label => 'ENTRY',
    help  => 'LDAP filter for entry which must exist');
$np->add_arg(
    spec  => 'nonentry_filter|E=s@',
    label => 'NONENTRY',
    help  => 'LDAP filter for entry which must *not* exist');
# FIXME add bind, search scope, etc

$np->getopts();

my $ldap = init_ldap($np->opts);

if ($np->opts->entry_filter) {
    for my $filter (@{$np->opts->entry_filter}) {
        check_ldap_entry($np, $ldap, $filter);
    }
}

if ($np->opts->nonentry_filter) {
    for my $filter (@{$np->opts->nonentry_filter}) {
        check_ldap_entry($np, $ldap, $filter, 1);
    }
}

$np->nagios_exit($np->check_messages);

sub check_ldap_entry {
    my ($nagios_plugin, $ldap, $ldap_filter, $negative_check) = @_;

    print "Checking filter '${ldap_filter}'\n"
        if $nagios_plugin->opts->verbose;

    my $result = $ldap->search(
        base    => $nagios_plugin->opts->base,
        scope   => $nagios_plugin->opts->scope,
        filter  => $ldap_filter);

    if ($result->code) {
        $nagios_plugin->add_message(WARNING, $result->error);
        return;
    }

    my $count = $result->count;

    my $check_fail = $negative_check ? ($count > 0) : ($count == 0);

    if ($check_fail) {
        $nagios_plugin->add_message(CRITICAL, "Filter '${ldap_filter}' matched $count times");
    }
}

sub init_ldap {
    my ($opts) = @_;

    my $ldap = Net::LDAP->new($opts->host);

    $ldap->bind;

    return $ldap;
}
