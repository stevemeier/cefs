#!/usr/bin/perl
#
# This script converts an XML input file to JSON output
# Pipe the output to `jq -S` for best results
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
  $xml = XMLin($xmlfile, ForceArray => [ qw(/keywords/ os_arch os_release packages) ] );
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

    ${$xml}{$advisory}{'id'} = $newkey;

   # ForceArray should take care of this,but it doesn't ¯\_(ツ)_/¯
   if (defined(${$xml}{$advisory}{'keywords'})) {
     push(@{${$xml}{$advisory}{'keywords2'}}, ${$xml}{$advisory}{'keywords'});
     ${$xml}{$advisory}{'keywords'} = ${$xml}{$advisory}{'keywords2'};
     delete(${$xml}{$advisory}{'keywords2'});
   }

    # Stick errata into an array
    push(@{${$xml}{'advisories'}}, ${$xml}{$advisory});

    # Remove original data
    delete ${$xml}{$advisory};
  }

}

print to_json($xml);

exit;
