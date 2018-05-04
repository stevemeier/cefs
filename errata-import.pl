#!/usr/bin/perl

# This script imports CentOS Errata into your Spacewalk
# It relies on preformatted information since parsing email
# is the road to madness...
#
# To run this script on CentOS 5.x you need 
# perl-XML-Simple, perl-Text-Unidecode and perl-Frontier-RPC
#
# Author: Steve Meier
#
# History:
# 20120206 - Initial version
# 20120501 - Modified to include details from Red Hat OVAL, use GetOpt
#            This change requires the perl module Text::Unidecode
# 20120507 - Added --publish
# 20120610 - Added type selection (Security, Bug Fix, Enhancement)
# 20120701 - Added --exclude-channels and --include-channels
# 20120707 - Added --sync-channels
# 20120916 - Restore channel membership of packages after publishing errata
#            Add CVEs to Security Errata
# 20120922 - Added user permission check
# 20120926 - Fix user permission check (Channel Admin works too)
# 20121105 - Added proper logout (via auth.logout)
# 20130114 - Added checking for existing errata. No longer requiers patched Frontier-Client.pm
# 20130214 - Fix warning if Red Hat OVAL file is not provided
# 20130214 - Small changes to allow Debian support
# 20130222 - Added support for keywords (such as reboot_suggested)
# 20130225 - Added a timer for re-authentication after 90 minutes
# 20130308 - Started working on update feature with code clean-ups
# 20130313 - Added support for API Version 12 in SW 1.9 (Thank you, James)
# 20130321 - Fixed channel sync for API Version 12
# 20130323 - Experimental support for updating existing Errata (adding packages)
# 20130909 - Added support for API Version 13 in SW 2.0 (Thank you, Alex)
# 20131213 - Merge patch from Aron Parsons to introduce --quiet
# 20140311 - Added support for API Version 14 in SW 2.1 (Thank you, Rolf)
# 20140316 - Fixed support for Version 14 (Thanks, Christian)
# 20140723 - Added support for API Version 15 in SW 2.2 (Thank you, Christian)
# 20140728 - Fixed a warning when importing Xen4CentOS errata (Thanks, Aron)
# 20140930 - Added --exclude-errata feature
# 20141002 - Fixed --exclude-errata feature
# 20141007 - Fixed supportedapi array (Thanks, Christian)
# 20150420 - Added support for API Version 16 in SW 2.3 (Thank you, Ugur and Bren)
# 20150630 - Fixed error message from eval_modules
# 20150719 - Updated code to satisfy perlcritic.com at severity level 4
# 20150731 - Added support to set issue date for errata
# 20150903 - Fixed error when setting issue date
# 20150906 - Merged code in GitHub, reapplying code changes from Perl::Critic (Level 4 and 5)
# 20151011 - Added support for API Version 17 in SW 2.4
# 20160317 - Fixed error in autopush that removed packages it shouldn't (Thanks, Helmut and Martin)
#            Made some changes suggested by perlcritic -3
# 20161214 - Added support for API Version 19 in SW 2.6
#            Added HTML::Entities to clean HTML codes from Debian errata
# 20161220 - Reworked the integratin of HTML::Entities which is now required
# 20161221 - Fix warning regarding missing issue_date on Debian errata
# 20170212 - Fix various checks on description field that where not called for Debian (Thanks, Bernhard)
# 20170930 - Added support for API Version 20 in SW 2.7
# 20180306 - Republish errata when packages are added
#            https://github.com/stevemeier/cefs/issues/4
# 20180307 - Report errata updated (not only created)
#            Fix accidental republishing of all errata
# 20180311 - Fix --sync-channels option
# 20180327 - Be more selective when re-publishing errata
#            https://github.com/stevemeier/cefs/issues/4
# 20180328 - Republishing was still not selective enough
#            Added support for API version 18 (SW 2.5)
# 20180419 - Added support for API Version 21 in SW 2.8
#            Severity is added to security errata on SW 2.8

# Load modules
use strict;
use warnings;
use Getopt::Long;
use IO::Handle;

# Test for required modules
&eval_modules;
import Frontier::Client;
import Text::Unidecode;
import XML::Simple;
import HTML::Entities;

# Version information
my $version = "20180419";
my @supportedapi = ( '10.9','10.11','11.00','11.1','12','13','13.0','14','14.0','15','15.0','16','16.0','17','17.0','18','18.0','19','19.0','20','20.0','21','21.0' );

# Disable output buffering
*STDOUT->autoflush();
*STDERR->autoflush();

# Spacewalk Version => API cheatsheet
# 0.6 => 10.9  == TESTED
# 0.7 => ??
# 0.8 => ??
# 1.0 => 10.11
# 1.1 => 10.11 == TESTED
# 1.2 => 10.15
# 1.3 => ??
# 1.4 => 10.16
# 1.5 => 11.00 == TESTED
# 1.6 => 11.1  == TESTED
# 1.7 => 11.1  == TESTED
# 1.8 => 11.1  == TESTED
# 1.9 => 12    == TESTED
# 2.0 => 13    == TESTED
# 2.1 => 14    == TESTED
# 2.2 => 15    == TESTED
# 2.3 => 16    == TESTED
# 2.4 => 17
# 2.5 => 18 ??
# 2.6 => 19
# 2.7 => 20
# 2.8 => 21

# Variable declation
my $server;
my $client;
my $apiversion;
my $apisupport = 0;
my ($xml, $erratafile, $rhsaxml, $rhsaovalfile);
my $session;
my (%name2id, %name2channel);
my @empty = ();
my $publish = 0; # do not publish by default
my $security = 0;
my $bugfix = 0;
my $enhancement = 0;
my $created = 0;
my $updated = 0;
my $debug = 0;
my $quiet = 0;
my $syncchannels = 0;
my $synccounter = 0;
my $synctimeout = 600;
my $getopt;
my ($channellist, $channel, @includechannels, @excludechannels);
my ($channeldetails, $lastmodified, $trackmodified, $lastsync, $synctimestamp);
my ($reference, @cves, @keywords, %erratadetails, %erratainfo);
my $result;
my $autopush = 0;
my (@autopushed, $undopush, @inchannel);
my %id2channel;
my ($pkg, $allpkg, $pkgdetails, $package);
my (@packages, @pkgids);
my @channels;
my ($advisory, $advid, $ovalid);
my $userroles;
my %existing;
my $authtime;
my $ignoreapiversion;
my $excludeerrata;

# Print call and parameters if in debug mode (GetOptions will clear @ARGV)
if (join(' ',@ARGV) =~ /--debug/) { print STDERR "DEBUG: Called as $0 ".join(' ',@ARGV)."\n"; }

# Parse arguments
$getopt = GetOptions( 'server=s'              => \$server,
                      'errata=s'              => \$erratafile,
                      'rhsa-oval=s'           => \$rhsaovalfile,
                      'debug'                 => \$debug,
                      'quiet'                 => \$quiet,
                      'publish'               => \$publish,
                      'security'              => \$security,
                      'bugfix'                => \$bugfix,
                      'enhancement'           => \$enhancement,
                      'sync-channels'         => \$syncchannels,
                      'sync-timeout=i'        => \$synctimeout,
                      'include-channels:s{,}' => \@includechannels,
                      'exclude-channels:s{,}' => \@excludechannels,
                      'autopush'              => \$autopush,
                      'ignore-api-version'    => \$ignoreapiversion,
                      'exclude-errata=s'      => \$excludeerrata
                     );

# Check for arguments
if (not(defined($erratafile))) { &usage; exit 1 };
if (not(defined($server))) { &usage; exit 1 };

# Do we have a proper errata file?
if (not(-f $erratafile)) {
  &error("$erratafile is not an errata file!\n");
  exit 1;
}

# Output $version string in debug mode
&debug("Version is $version\n");

#############################
# Initialize API connection #
#############################
$client = Frontier::Client->new(url => "http://$server/rpc/api");

#########################################
# Get the API version we are talking to #
#########################################
if ($apiversion = $client->call('api.get_version')) {
  &info("Server is running API version $apiversion\n");
} else {
  &error("Could not determine API version on server\n");
  exit 1;
}

#####################################
# Check if API version is supported #
#####################################
foreach (@supportedapi) {
  if ($apiversion eq $_) {
    &info("API version $apiversion is supported\n");
    $apisupport = 1;
  }
}

# In case we found an unsupported API
if (not($apisupport)) {
  if ($ignoreapiversion) {
    &warning("API version $apiversion has not been tested but you wanted to continue.\n");
  } else {
    &error("API version $apiversion is not supported. Try upgrading this script\n");
    &error("or try the --ignore-api-version at your own risk.\n");
    exit 2;
  }
}

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

# Call login and check session id
&login;
if ($session =~ /^\w+$/) {
  &info("Authentication successful\n");
} else {
  &error("Authentication FAILED!\n");
  exit 3;
} 

##########################
# Check user permissions #
##########################
if ($publish) {
  # Publishing Errata requires Satellite or Org Administrator role
  $userroles = $client->call('user.list_roles', $session, "$ENV{'SPACEWALK_USER'}");  

  &debug("User is assigned these roles: ".join(' ', @{$userroles})."\n");

  if ( (join(' ', @{$userroles}) =~ /satellite_admin/) || 
       (join(' ', @{$userroles}) =~ /org_admin/) ||
       (join(' ', @{$userroles}) =~ /channel_admin/) ) {
    &info("User has administrator access to this server\n");
  } else {
    &error("User does NOT have administrator access\n");
    &error("You have set --publish but your user has insufficient access rights\n");
    &error("Either use an account that is Satellite/Org/Channel Administator or omit --publish\n");
    &logout;
    exit 1;
  }
}

############################
# Read the XML errata file #
############################
&info("Loading errata XML\n");
if (not($xml = XMLin($erratafile))) {
  &error("Could not parse errata file!\n");
  exit 4;
}
&debug("XML loaded successfully\n");

# Check that we can handle the data
if (defined($xml->{meta}->{minver})) {
  if ($xml->{meta}->{minver} > $version) {
    &error("This script is too old to handle this data file. Please update.\n");
    exit 5;
  }
}

##################################
# Load optional Red Hat OVAL XML #
##################################
if (defined($rhsaovalfile)) {
  if (-f $rhsaovalfile) {
    &info("Loading Red Hat OVAL XML\n");
    if (not($rhsaxml = XMLin($rhsaovalfile))) {
      &error("Could not parse Red Hat OVAL file!\n");
      exit 4;
    }

    &debug("Red Hat OVAL XML loaded successfully\n");
  }
}

##################################
# Check if syncRepo is supported #
##################################
if ($syncchannels) {
  # API Version must be at least 11
  unless ($apiversion >= 11) {
    &warning("This API version does not support synching\n");
    $syncchannels = 0;
  }
}

########################
# Get server inventory #
########################
&info("Getting server inventory\n");

# Get a list of all channels
$channellist = $client->call('channel.list_all_channels', $session);

if (scalar(@includechannels) > 0) { &debug("--include-channels set: ".join(" ", @includechannels)."\n"); }
if (scalar(@excludechannels) > 0) { &debug("--exclude-channels set: ".join(" ", @excludechannels)."\n"); }

# Collect unpublished errata
&info("Checking for unpublished errata\n");
my $unpuberrata = $client->call('errata.list_unpublished_errata', $session);
foreach my $errata (@$unpuberrata) {
  &debug("Found unpublished errata for $errata->{'advisory_name'}\n");
  $existing{$errata->{'advisory_name'}} = 1;
}

# Go through each channel 
foreach my $channel (sort(@$channellist)) {

  # Collect existing errata
  my $channelerrata = $client->call('channel.software.list_errata', $session, $channel->{'label'});
  foreach my $errata (@$channelerrata) {
    &debug("Found existing errata for $errata->{'advisory_name'}\n");
    $existing{$errata->{'advisory_name'}} = 1;
  }

  # Check if channel is included
  if (scalar(@includechannels) > 0) {
    if (not(grep { /$channel->{'label'}/ } @includechannels)) {
      &info("Channel $channel->{'name'} ($channel->{'label'}) is NOT included\n");
      next;
    }
  }

  # Check if channel is excluded
  if (scalar(@excludechannels) > 0) {
    if (grep { /$channel->{'label'}/ } @excludechannels ) {
      &info("Excluding channel $channel->{'name'} ($channel->{'label'})\n");
      next;
    }
  }

  # Sync channels to repo before scanning
  if ($syncchannels) {
    &debug("Getting channel.software.get_details for $channel->{'label'}\n");
    $channeldetails = $client->call('channel.software.get_details', $session, $channel->{'label'});
    if (defined($channeldetails->{'yumrepo_last_sync'})) {
      $lastsync = sprintf("%d-%02d-%02d%s%s", unpack('A4A2A2AA8', $channeldetails->{'yumrepo_last_sync'}->value()));
    } else {
      $lastsync = "never";
    }
    if (defined($channeldetails->{'last_modified'})) {
      $lastmodified = sprintf("%d-%02d-%02d%s%s", unpack('A4A2A2AA8', $channeldetails->{'last_modified'}->value()));
    } else {
      $lastmodified = "never";
    }

    &info("Starting Repository Sync for $channel->{'name'}\n");
    if ($client->call('channel.software.sync_repo', $session, $channel->{'label'})) {
      # Wait for spacewalk-repo-sync to complete
      $synctimestamp = $lastsync;
      while ($synctimestamp eq $lastsync) {
        if ($channeldetails = $client->call('channel.software.get_details', $session, $channel->{'label'})) {
          $synctimestamp = sprintf("%d-%02d-%02d%s%s", unpack('A4A2A2AA8', $channeldetails->{'yumrepo_last_sync'}->value()));

          $trackmodified = $lastmodified;
          $lastmodified = sprintf("%d-%02d-%02d%s%s", unpack('A4A2A2AA8', $channeldetails->{'last_modified'}->value()));
          &info("Sync for $channel->{'name'} is still in progress (Last modified: $lastmodified)\n");

          # Check if the channel has been modified (e.g. by adding new packages)
          if ($trackmodified eq $lastmodified) { $synccounter += 30; &debug("Synccounter set to $synccounter\n"); };
          if ($trackmodified ne $lastmodified) { $synccounter  =  0; &debug("Synccounter set to $synccounter\n"); };

          # Channel is no longer being updated but lastsync hasn't changed. Sync might have failed for some reason
          if ($synccounter >= $synctimeout) { &warning("Sync Timeout reached. Please check your reposync log for details\n"); last; }

          sleep 30;
        } else {
          &warning("Could not get Channel Details. Will try again\n");
          sleep 1;
        }
      }
      &info("Sync for $channel->{'name'} finished\n");
    } else {
      &error("Repository Sync for $channel->{'name'} FAILED\n");
    }
  }

  &info("Scanning channel $channel->{'name'}\n");

  # Get all packages in current channel
  $allpkg = $client->call('channel.software.list_all_packages', $session, $channel->{'label'});

  # Go through each package
  foreach my $pkg (@$allpkg) {

    # Get the details of the current package
    $pkgdetails = $client->call('packages.get_details', $session, $pkg->{id});
    &debug("Package ID $pkg->{id} is $pkgdetails->{'file'}\n");
    $name2id{$pkgdetails->{'file'}} = $pkg->{id};
    $name2channel{$pkgdetails->{'file'}} = $channel->{'label'};
    push(@{$id2channel{$pkg->{id}}}, $channel->{'label'}); 
  }
}

##############################
# Process errata in XML file #
##############################

# Go through each <errata>
foreach my $advisory (sort(keys(%{$xml}))) {

  # Check for reauthentication
  if (time > ($authtime + 5400)) { &reauthenticate; }

  # Restore "proper" name of adivsory
  $advid = $advisory;
  $advid =~ s/--/:/;
  
  @packages = ();
  @channels = ();
  @cves = ();
  @keywords = ();

  # Only consider CentOS (and Debian) errata
  unless($advisory =~ /^CE|^DSA/) { &debug("Skipping $advid\n"); next; }

  # Check if errata matches --exclude-errata 
  if (defined($excludeerrata)) {
    if ($advid =~ /$excludeerrata/i) { &notice("Excluding $advid\n"); next; }
  }

  # Check command line options for errata to consider
  if ($security || $bugfix || $enhancement) {
    if ( ($advisory =~ /^CESA/) && (not($security)) ) {
      &debug("Skipping $advid. Security Errata not selected.\n");
      next;
    }

    if ( ($advisory =~ /^CEBA/) && (not($bugfix)) ) {
      &debug("Skipping $advid. Bugfix Errata not selected.\n");
      next;
    }

    if ( ($advisory =~ /^CEEA/) && (not($enhancement)) ) {
      &debug("Skipping $advid. Enhancement Errata not selected.\n");
      next;
    }
  }

  # Start processing
  &debug("Processing $advid\n");

  # Generate OVAL ID for security errata
  $ovalid = "";
  if ($advid =~ /CESA/) {
    if ($advid =~ /CESA-(\d+):(\d+)/) {
      $ovalid = "oval:com.redhat.rhsa:def:$1".sprintf("%04d", $2);
      &debug("Processing $advid -- OVAL ID is $ovalid\n");
    }
  }

  # Check if the errata already exists
  if (not(defined($existing{$advid}))) {
    # Errata does not exist yet
    
    # Find package IDs mentioned in errata
    &find_packages($advisory);

    # Create Errata Info hash
    %erratainfo = ( "synopsis"         => "$xml->{$advisory}->{synopsis}",
                    "advisory_name"    => "$advid",
                    "advisory_release" => int($xml->{$advisory}->{release}),
                    "advisory_type"    => "$xml->{$advisory}->{type}",
                    "product"          => "$xml->{$advisory}->{product}",
                    "topic"            => "$xml->{$advisory}->{topic}",
                    "description"      => "$xml->{$advisory}->{description}",
                    "references"       => "$xml->{$advisory}->{references}",
                    "notes"            => "$xml->{$advisory}->{notes}",
                    "solution"         => "$xml->{$advisory}->{solution}" );

    # Insert description from Red Hat OVAL file, if available (only for Security)
    if (defined($ovalid)) {
      if ( defined($rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{description}) ) {
        &debug("Using description from $ovalid\n");
        $erratainfo{'description'} = $rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{description};
	# 20161214: Remove HTML encodings (ATIX Debian Errata)
	# 20161220: Always exceute as HTML::Entities is now required
	decode_entities($erratainfo{'description'}); 
        # Remove Umlauts -- API throws errors if they are included
        $erratainfo{'description'} = unidecode($erratainfo{'description'});
        # Limit to length of 4000 bytes (see https://www.redhat.com/archives/spacewalk-list/2012-June/msg00128.html)
        if (length($erratainfo{'description'}) > 4000) {
          $erratainfo{'description'} = substr($erratainfo{'description'}, 0, 4000);
        } 
        # Add Red Hat's Copyright notice to the Notes field
        if ( defined($rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{advisory}->{rights}) ) {
          $erratainfo{'notes'}  = "The description and CVE numbers have been taken from Red Hat OVAL definitions.\n\n";
          $erratainfo{'notes'} .= $rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{advisory}->{rights};
        }
      }
 
      # Sanitize the description field, if set (20170212: moved down into separate block)
      if (defined($erratainfo{'description'})) {
        # 20161214: Remove HTML encodings (ATIX Debian Errata)
        # 20161220: Always exceute as HTML::Entities is now required
        decode_entities($erratainfo{'description'}); 
        # Remove Umlauts -- API throws errors if they are included
        $erratainfo{'description'} = unidecode($erratainfo{'description'});

        # Limit to length of 4000 bytes (see https://www.redhat.com/archives/spacewalk-list/2012-June/msg00128.html)
        if (length($erratainfo{'description'}) > 4000) {
          $erratainfo{'description'} = substr($erratainfo{'description'}, 0, 4000);
        }
      }

      # Create an array of CVEs from Red Hat OVAL file to add to Errata later
      if ( ref($rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{reference}) eq 'ARRAY') {
        foreach my $reference (@{$rhsaxml->{definitions}->{definition}->{$ovalid}->{metadata}->{reference}}) {
          if ($reference->{source} eq 'CVE') {
             push(@cves, $reference->{ref_id});
          }
        }
      }

    }

    # Handle CVEs attached to Debian announcements
    if (defined($xml->{$advisory}->{cves})) {
      if ( ref($xml->{$advisory}->{cves}) eq 'ARRAY') {
        foreach my $cve ( @{$xml->{$advisory}->{cves}} ) {
          push(@cves, $cve);
        }
      } else {
        # one CVE only
	push(@cves, $xml->{$advisory}->{cves});
      }
    }

    # Handle keywords attached to CentOS/Debian announcements
    if (defined($xml->{$advisory}->{keywords})) {
      if ( ref($xml->{$advisory}->{keywords}) eq 'ARRAY') {
        foreach my $keyword ( @{$xml->{$advisory}->{keywords}} ) {
          push(@keywords, $keyword);
        }
      } else {
        # one keyword only
        push(@keywords, $xml->{$advisory}->{keywords});
      }
    }

    if (@packages >= 1) {
      # If there is at least one matching package create the errata?
      if ( ref($xml->{$advisory}->{packages}) eq 'ARRAY') {
        &info("Creating errata for $advid ($xml->{$advisory}->{synopsis}) (".($#packages +1)." of ".($#{$xml->{$advisory}->{packages}} +1).")\n");
      } else {
        &info("Creating errata for $advid ($xml->{$advisory}->{synopsis}) (1 of 1)\n");
      }
      $result = $client->call('errata.create', $session, \%erratainfo, \@empty, \@empty, \@packages, $client->boolean(0), \@channels);
      if (defined($result->{faultCode})) {
        &error("Creating Errata $advid FAILED\n");
      } else {
        $created++;

        # Add keywords
        if (@keywords >= 1) {
          &info("Adding keywords to $advid\n");
          &debug("Keywords in $advid: ".join(',', @keywords)."\n");
          %erratadetails = ( "keywords" => [ @keywords ] );
          $result = $client->call('errata.set_details', $session, $advid, \%erratadetails);
        }

        # Add issue date (requires API version 12 or higher)
        if ($apiversion >= 12) {
          if (defined($xml->{$advisory}->{issue_date})) {
            if ($xml->{$advisory}->{issue_date} =~ /(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2}:\d{2})/) {
              &info("Adding issue date to $advid\n");
              undef %erratadetails;
              $erratadetails{'issue_date'} = $client->date_time("$1$2$3T$4");
              $erratadetails{'update_date'} = $client->date_time("$1$2$3T$4");
              $result = $client->call('errata.set_details', $session, $advid, \%erratadetails);
            } else {
              &warning("$advid has no proper issue date\n");
            }
          }
        }

	# Add severity to security errata (requires API version 21 or higher)
	if ($apiversion >= 21) {
          if ($advid =~ /CESA/ix) {
	    if (defined($xml->{$advisory}->{severity})) {
              if ( ($xml->{$advisory}->{severity} eq 'Low') ||
	           ($xml->{$advisory}->{severity} eq 'Moderate') ||
		   ($xml->{$advisory}->{severity} eq 'Important') ||
		   ($xml->{$advisory}->{severity} eq 'Critical') ){

                &info("Adding severity (".$xml->{$advisory}->{severity}.") to $advid\n");
                undef %erratadetails;
                $erratadetails{'severity'} = $xml->{$advisory}->{severity};
                $result = $client->call('errata.set_details', $session, $advid, \%erratadetails);
              }
	    }
          }
	}

        # Do extra stuff if --publish is set
        if ($publish) {
          # Publish the Errata (seperated from creation on purpose)
          &info("Publishing Errata for $advid\n");
          $result = $client->call('errata.publish', $session, $advid, \@channels);
          if (defined($result->{faultCode})) { &error("Publishing Errata $advid FAILED\n"); }

          # CVEs can only be added to published errata. Why? I have no idea.
          if (@cves >= 1) {
            &info("Adding CVE information to $advid\n");
            &debug("CVEs in $advid: ".join(',', @cves)."\n");
            %erratadetails = ( "cves" => [ @cves ] );
            $result = $client->call('errata.set_details', $session, $advid, \%erratadetails);
          }
          
          # Reverse useless copying of packages around by publish
          if (not($autopush)) {
            foreach my $pkg (@packages) {
              # Log previous and current channel membership
              @autopushed = ();
              @inchannel = ();
              &debug("Previous channel membership for $pkg: ".join(',',@{$id2channel{$pkg}})."\n");
              $channellist = $client->call('packages.list_providing_channels', $session, $pkg);
              foreach my $channel (@$channellist) {
                 push(@inchannel, $channel->{label});
              }
              &debug("Current channel membership for $pkg: ".join(',',@inchannel)."\n");

              @autopushed = only_in_first(\@inchannel, \@{$id2channel{$pkg}});
              @autopushed = &uniq(@autopushed);

              # Remove packages from channel(s) it didn't belong to earlier
              if (@autopushed >= 1) {
                &debug("Package $pkg has been auto-pushed to ".join(',',@autopushed)."\n");
                foreach my $undopush (@autopushed) {
                  &debug("Removing package $pkg from $undopush\n");
                  $result = $client->call('channel.software.remove_packages', $session, $undopush, $pkg);
                }
              } 
            }
          }

        }
      }
    } else {
      # There is no related package so there is no errata created
      &notice("Skipping errata $advid ($xml->{$advisory}->{synopsis}) -- No packages found\n");
    }

  } else {
    &info("Errata for $advid already exists\n");
    &list_packages($advid);
    &find_packages($advisory);

    # Did we find more packages than currently associated?
    if (@packages > @pkgids) {
      &info("Adding packages to $advid\n");
      # Maybe we just need this one call
      my $addpackages = $client->call('errata.add_packages', $session, $advid, \@packages);
      $updated++;
    
      if ($publish) {
        # Check which channels the errata currently applies to
        # We should not republish to this channel, only to new ones
        my $applicable = $client->call('errata.applicable_to_channels', $session, $advid);

        # Put data into a more handy array
        my @applicablechannels;
        foreach (@{$applicable}) { push(@applicablechannels, $_->{'label'}) }

        my @repubchannels;
        foreach my $pkg (@packages) {
          foreach my $channel (only_in_first(\@{$id2channel{$pkg}}, \@applicablechannels)) {
            push(@repubchannels, $channel);
          }
        }

        @repubchannels = &uniq(@repubchannels);
            
        &info("Republishing $advid\n");
        &debug("Republishing $advid to channel ".join(',',@repubchannels)."\n");
        my $addpackages = $client->call('errata.publish', $session, $advid, \@repubchannels);
        
      }
    }

  }
}

# FIN
&info("Errata created: $created\n");
&info("Errata updated: $updated\n");
if (not($publish)) {
  &info("Errata have been created but NOT published!\n");
  &info("Please go to: Errata -> Manage Errata -> Unpublished to find them\n");
  &info("If you want to publish them please delete the unpublished Errata and run this script again\n");
  &info("with the --publish parameter\n");
}
&logout;
exit;

# SUBS
sub debug {
  if ($debug) { print "DEBUG: @_"; }
  return;
}

sub info {
  if ($quiet) { return; }
  print "INFO: @_";
  return;
}

sub warning {
  print "WARNING: @_";
  return;
}

sub error {
  print "ERROR: @_";
  return;
}

sub notice {
  if ($quiet) { return; }
  print "NOTICE: @_";
  return;
}

sub usage {
  print "Usage: $0 --server <SERVER> --errata <ERRATA-FILE>\n";
  print "       [ --rhsa-oval <REDHAT-OVAL-XML> |\n";
  print "         --include-channels=<CHANNELS> | --exclude-channels=<CHANNELS> |\n";
  print "         --sync-channels | --sync-timeout=<TIMEOUT> |\n";
  print "         --bugfix | --security | --enhancement |\n";
  print "         --publish | --autopush | --ignore-api-version\n";
  print "         --exclude-errata=<REGEX>\n";
  print "         --quiet | --debug ]\n";
  print "\n";
  print "REQUIRED:\n";
  print "  --server\t\tThe hostname or IP address of your spacewalk server\n";
  print "  --errata\t\tThe XML file containing errata information\n";
  print "\n";
  print "OPTIONAL:\n";
  print "  --rhsa-oval\t\tOVAL XML file from Red Hat (recommended)\n";
  print "  --include-channels\tOnly consider certain channels (seperated by comma)\n";
  print "  --exclude-channels\tIgnore certain channels (seperated by comma)\n";
  print "  --sync-channels\tSync channel with associated repository before scanning\n";
  print "  --sync-timeout\tAbort sync after n seconds stalled (default: 600)\n";
  print "  --bugfix\t\tImport Bug Fix Advisories [CEBA] (default: all)\n";
  print "  --security\t\tImport Security Advisories [CESA] (default: all)\n";
  print "  --enhancement\t\tImport Enhancement Advisories [CEEA] (default: all)\n";
  print "  --publish\t\tPublish errata after creation (default: unpublished)\n";
  print "  --autopush\t\tAllow server to copy packages around (NOT recommended)\n";
  print "  --ignore-api-version\tContinue if the API version is untested (usually safe)\n";
  print "  --exclude-errata\tExclude Errata that match provided regex\n";
  print "\n";
  print "LOGGING:\n";
  print "  --quiet\t\tOnly print warnings and errors\n";
  print "  --debug\t\tSet verbosity to debug (use this when reporting issues!)\n";
  print "\n";
  return;
}

sub eval_modules {
  eval {
    require Frontier::Client;
    1;
  } or do {
    die "ERROR: You are missing Frontier::Client\n       CentOS: yum install perl-Frontier-RPC\n";
  };

  eval { 
    require Text::Unidecode; 
    1;
  } or do {
    die "ERROR: You are missing Text::Unidecode\n       CentOS: yum install perl-Text-Unidecode\n";
  };

  eval { 
    require XML::Simple;
    1;
  } or do {
    die "ERROR: You are missing XML::Simple\n       CentOS: yum install perl-XML-Simple\n";
  };

  eval {
    require HTML::Entities;
    1;
  } or do {
    die "ERROR: You are missing HTML::Entities\n       CentOS: yum install perl-HTML-Parser\n";
  };

  return;
}

sub uniq {
  my (@input) = @_;
  my %all = ();
  @all{@input} = 1;
  return (keys %all);
}

sub login {
  $session = $client->call('auth.login', "$ENV{'SPACEWALK_USER'}", "$ENV{'SPACEWALK_PASS'}");
  $authtime = time;
  return;
}

sub logout {
  &debug("Logging out.\n");
  $client->call('auth.logout', $session);
  return;
}

sub reauthenticate {
  &info("Reauthentication required\n");

  &debug("Current Session ID: $session\n");
  &logout;

  &login;
  &debug("New Session ID: $session\n");
  return;
}

sub find_packages {
  my ($advisory) = @_;
  #  INPUT: Advisory, e.g. CESA-2013:0123
  # OUTPUT: Array of Package IDs, Array of Channel Labels

  # Find package IDs mentioned in errata
  if ( ref($xml->{$advisory}->{packages}) eq 'ARRAY') {
    foreach my $package ( @{$xml->{$advisory}->{packages}} ) {
      if (defined($name2id{$package})) {
        # We found it, nice
        &debug("Package: $package -> $name2id{$package} -> $name2channel{$package} \n");
        push(@packages, $name2id{$package});
        push(@channels, $name2channel{$package});
        # Ugly hack :)
        @packages = &uniq(@packages);
        @channels = &uniq(@channels);
       } else {
         # No such package, too bad
         &debug("Package: $package not found\n");
       }
     }
  } else {
    # errata has only one package
    if (defined($name2id{$xml->{$advisory}->{packages}})) {
      # the one and only package is found
      &debug("Package: $xml->{$advisory}->{packages} -> $name2id{$xml->{$advisory}->{packages}} -> $name2channel{$xml->{$advisory}->{packages}} \n");
      push(@packages, $name2id{$xml->{$advisory}->{packages}});
      push(@channels, $name2channel{$xml->{$advisory}->{packages}});
    } else {
      # no hit
      &debug("Package: $xml->{$advisory}->{packages} not found\n");
    }
  }

  return;
}

sub list_packages {
  my ($advisory) = @_;
  #  INPUT: Advisory, e.g. CESA-2013:0123
  # OUTPUT: Array of Package IDs
 
  @pkgids = ();
  my $listpackages = $client->call('errata.list_packages', $session, $advisory);
  foreach my $package (@$listpackages) {
    push(@pkgids, $package->{'id'});
  }

  &debug("$advisory packages: ".join(' ',@pkgids)."\n");

  return;
}

sub only_in_first {
  my ($list1, $list2) = @_;
  my @output;
  my %listhash;

  # Transform array into hash for quicker access
  foreach (@{$list2}) { $listhash{$_} = 1; }

  # Check each entry in list1 against list2
  foreach (@{$list1}) {
    if (not(defined($listhash{$_}))) {
      push(@output, $_);
    }
  }

  # Return entries that are in list1 but not list2
  return @output;
}
