#!/usr/bin/perl
#
# This script converts an XML input file to JSON output
# Author: Steve Meier

use strict;
use warnings;
use Getopt::Long;
use JSON qw(to_json);
use XML::Simple;

my ($xmlfile, $xml);
my $getopt = GetOptions('in=s' => \$xmlfile);

if (not(defined($xmlfile))) {
  print "ERROR: Please define --in <xmlfile>\n";
  exit 1;
}

if (-r $xmlfile) {
  $xml = XMLin($xmlfile, ForceArray => 1);
} else {
  print "ERROR: Could not read $xmlfile\n";
  exit 1;
}

foreach my $advisory (sort(keys(%{$xml}))) {
  my $newkey;
  if ($advisory =~ /^CE/) {
    $newkey = $advisory;
    # Use proper advisory name
    $newkey =~ s/--/:/;
    # Remove unnecessary array strucutre
    ${$xml}{$newkey} = ${$xml}{$advisory}[0];
    # Remove original data
    delete ${$xml}{$advisory};
  }
}

print to_json($xml, {'pretty' => '1'});

exit;
