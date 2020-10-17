#!/usr/bin/perl
#
# This script deletes all existing errata from a Spacewalk server

# Test for required modules
&eval_modules;

# Load modules
use strict;
use warnings;
use Getopt::Long;
import Frontier::Client;

# Variables
my $server;
my $debug = 0;
my $deleted = 0;
my %existing;

# Parse arguments
GetOptions( 'server=s' => \$server,
            'debug'    => \$debug,
           );

####################
# Check parameters #
####################
if (not(defined($server))) {
  &error("Please define a server (--server)\n");
  exit(1);
}

#############################
# Initialize API connection #
#############################
my $client = new Frontier::Client(url => "http://$server/rpc/api");

###########################
# Authenticate to the API #
###########################
if (not(defined($ENV{'SPACEWALK_USER'}))) {
  &error("\$SPACEWALK_USER not set\n");
  exit 3;
}
if (not(defined($ENV{'SPACEWALK_PASS'}))) {
  &error("\$SPACEWALK_PASS not set\n");
  exit 3;
}

my $session = $client->call('auth.login', "$ENV{'SPACEWALK_USER'}", "$ENV{'SPACEWALK_PASS'}");
if ($session =~ /^\w+$/) {
  &info("Authentication successful\n");
} else {
  &error("Authentication FAILED!\n");
  exit 3;
} 

# Collect unpublished errata
&info("Checking for unpublished errata\n");
my $unpuberrata = $client->call('errata.list_unpublished_errata', $session);
foreach my $errata (@$unpuberrata) {
  &debug("Found unpublished errata for $errata->{'advisory_name'}\n");
  $existing{$errata->{'advisory_name'}} = 1;
}

my $channellist = $client->call('channel.list_all_channels', $session);
# Go through each channel 
foreach my $channel (sort(@$channellist)) {

  # Collect existing errata
  my $channelerrata = $client->call('channel.software.list_errata', $session, $channel->{'label'});
  foreach my $errata (@$channelerrata) {
    &debug("Found existing errata for $errata->{'advisory_name'} in $channel->{'label'}\n");
    $existing{$errata->{'advisory_name'}} = 1;
  }
}

&info("Errata collection finished\n");

foreach my $errata (keys(%existing)) {
  my @removepkg = ();
  my $packages = $client->call('errata.list_packages', $session, $errata);
  foreach (@$packages) {
    &info("$errata links to package $_->{id}\n");
    push(@removepkg, $_->{id});
  }

  if (@removepkg >= 1) {
    &info("Removing packages from $errata\n");
    $client->call('errata.remove_packages', $session, $errata, [ @removepkg ]);
  }

  &info("Deleting errata $errata\n");
  $client->call('errata.delete', $session, $errata);
  $deleted++;
}

&info("Deleted $deleted errata\n");
exit;

# SUBS
sub debug() {
  if ($debug) { print "DEBUG: @_"; }
}

sub info() {
  print "INFO: @_";
}

sub warning() {
  print "WARNING: @_";
}

sub error() {
  print "ERROR: @_";
}

sub notice() {
  print "NOTICE: @_";
}

sub eval_modules() {
  eval { require Frontier::Client; };
  if ($@) { die "ERROR: You are missing Frontier::Client\n       CentOS: yum install perl-Frontier-RPC\n"; };
}
