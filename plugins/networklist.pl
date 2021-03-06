#-----------------------------------------------------------
# networklist.pl - Plugin to extract information from the 
#   NetworkList key, including the MAC address of the default
#   gateway
#
#
# Change History:
#    20161115 - Updated to include profile GUIDs, DNS, and gateway addresses for Nla\Cache data
#    20150812 - updated to include Nla\Cache data
#    20120917 - updated to include NameType value
#    20090812 - updated code to parse DateCreated and DateLastConnected
#               values; modified output, as well
#    20090811 - created
#
# References
#
# copyright 2015 Quantum Analytics Research, LLC
# Author: H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package networklist;
use strict;

my %config = (hive          => "Software",
            osmask        => 22,
            hasShortDescr => 1,
            hasDescr      => 0,
            hasRefs       => 0,
            version       => 20161115);

sub getConfig{return %config}

sub getShortDescr {
	return "Collects network info from Vista+ NetworkList key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

my %types = (0x47 => "wireless",
           0x06 => "wired",
           0x17 => "broadband (3g)");

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching networklist v.".$VERSION);
	::rptMsg("Launching networklist v.".$VERSION);
  ::rptMsg("(".getHive().") ".getShortDescr()."\n");
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $base_path = "Microsoft\\Windows NT\\CurrentVersion\\NetworkList";
	
# First, get profile info	
	my $key_path = $base_path."\\Profiles";
	my $key;
	my %nl; # hash of hashes to hold data
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
	
		my @sk = $key->get_list_of_subkeys();
		if (scalar(@sk) > 0) {
			foreach my $s (@sk) {
				my $name = $s->get_name();
				$nl{$name}{LastWrite} = $s->get_timestamp();
				eval {
					$nl{$name}{ProfileName} = $s->get_value("ProfileName")->get_data();
					$nl{$name}{Description} = $s->get_value("Description")->get_data();
					$nl{$name}{Managed} = $s->get_value("Managed")->get_data();
					
					my $create = $s->get_value("DateCreated")->get_data();
					$nl{$name}{DateCreated} = parseDate128($create) if (length($create) == 16);
					my $conn   = $s->get_value("DateLastConnected")->get_data();
					$nl{$name}{DateLastConnected} = parseDate128($conn) if (length($conn) == 16);
					
					$nl{$name}{NameType} = $s->get_value("NameType")->get_data();
					
					if (exists $types{$nl{$name}{NameType}}) {
						$nl{$name}{Type} = $types{$nl{$name}{NameType}};
					}
					else {
						$nl{$name}{Type} = $nl{$name}{NameType};
					}
					
				};
			}

# Get additional information from the Signatures subkey
			$key_path = $base_path."\\Signatures\\Managed";
			if ($key = $root_key->get_subkey($key_path)) { 
				my @sk = $key->get_list_of_subkeys();
				if (scalar(@sk) > 0) {
					foreach my $s (@sk) {
						eval {
							my $prof = $s->get_value("ProfileGuid")->get_data();
							my $dns = $s->get_value("DnsSuffix")->get_data();
							$nl{$prof}{DnsSuffix} = $dns;
							my $tmp = substr($s->get_value("DefaultGatewayMac")->get_data(),0,6);
							$nl{$prof}{DefaultGatewayMac} = parseMacAddr($tmp);
						};
					}
				}
			}
		
			$key_path = $base_path."\\Signatures\\Unmanaged";
			if ($key = $root_key->get_subkey($key_path)) { 
				my @sk = $key->get_list_of_subkeys();
				if (scalar(@sk) > 0) {
					foreach my $s (@sk) {
						eval {
							my $prof = $s->get_value("ProfileGuid")->get_data();
							my $dns = $s->get_value("DnsSuffix")->get_data();
							$nl{$prof}{DnsSuffix} = $dns;
							my $tmp = substr($s->get_value("DefaultGatewayMac")->get_data(),0,6);
							$nl{$prof}{DefaultGatewayMac} = parseMacAddr($tmp);
						};
					}
				}
			}
			
# Now, display the information			
			foreach my $n (keys %nl) {
				::rptMsg($nl{$n}{ProfileName});
				::rptMsg("  Key LastWrite    : ".gmtime($nl{$n}{LastWrite})." Z");
				::rptMsg("  DateLastConnected: ".$nl{$n}{DateLastConnected});
				::rptMsg("  DateCreated      : ".$nl{$n}{DateCreated});
				::rptMsg("  DefaultGatewayMac: ".$nl{$n}{DefaultGatewayMac});
				::rptMsg("  Type             : ".$nl{$n}{Type});
				::rptMsg("  Profile GUID     : ".$n);
				::rptMsg("  DNS Suffix       : ".$nl{$n}{DnsSuffix});
				::rptMsg("");
			}
			
		}
		else {
			::rptMsg($key_path." has not subkeys");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	::rptMsg("");
# Harvest network card information
	$key_path = "Microsoft\\Windows NT\\CurrentVersion\\NetworkCards";
	$key;
	my %nc;
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $service = $s->get_value("ServiceName")->get_data();
				$nc{$service}{descr} = $s->get_value("Description")->get_data();
			}
		}
	}

# Get NLA info
	$key_path = $base_path."\\Nla\\Cache\\Intranet";
	if ($key = $root_key->get_subkey($key_path)) { 
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			::rptMsg(sprintf "%-26s  %-38s  %-17s  %-30s","Date","Interface","Gateway Address","Domain/IP");
			foreach my $s (@subkeys) {
				my $net_time         = $s->get_timestamp();
				my $net_name         = $s->get_name();
				my @net_gateway_vals = $s->get_list_of_values();
				my $net_gateway_s;
				my $nic;
				if(scalar(@net_gateway_vals) > 0) {
					foreach my $val (@net_gateway_vals) {
						#Note, this will only take one NIC per entry. 
						#Unsure if it needs to support the potential for multiple
						if(exists($nc{$val->get_name()})) {
							$net_gateway_s = $val->get_data();
							$nic = $val->get_name();
						}
					}
				}
				my $net_gateway_addr = "";
				if($net_gateway_s) {
					$net_gateway_addr = parseMacAddr($net_gateway_s);
				}
				::rptMsg(sprintf "%-26s  %-38s  %-17s  %-30s",gmtime($net_time)." Z",$nic,$net_gateway_addr,$net_name);
			}
		}
	}
}

# Function takes in the data from a registry value, expecting it to contain a MAC address
# Function returns the MAC address formatted as 12-34-56-78-90-ab
sub parseMacAddr {
	my $data = shift();
	my $mac = uc(unpack("H*",$data));
	my @t = split(//,$mac);
	my $gateway = $t[0].$t[1]."-".$t[2].$t[3]."-".$t[4].$t[5]."-".$t[6].$t[7]."-".$t[8].$t[9]."-".$t[10].$t[11]; 
	return $gateway;
}

sub parseDate128 {
	my $date = $_[0];
	my @months = ("Jan","Feb","Mar","Apr","May","Jun","Jul",
	              "Aug","Sep","Oct","Nov","Dec");
	my @days = ("Sun","Mon","Tue","Wed","Thu","Fri","Sat");
	my ($yr,$mon,$dow,$dom,$hr,$min,$sec,$ms) = unpack("v*",$date);
	$hr = "0".$hr if ($hr < 10);
	$min = "0".$min if ($min < 10);
	$sec = "0".$sec if ($sec < 10);
	my $str = $days[$dow]." ".$months[$mon - 1]." ".$dom." ".$hr.":".$min.":".$sec." ".$yr;
	return $str;
}
1;
