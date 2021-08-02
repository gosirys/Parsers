#!/usr/bin/perl

# by ME
# Parses Nessus reports and creates an HTML report with nice tables, summary stats, ready to copy and paste in MS Word
# Useful for Vulnerability Assessments to get Nessus Findings into a Word document
# needs report .nessus format
# prints 2 tables, one for the actual general poor patch etc finding, and a detailed one for the appendix


# The CVSS report shows vulnerabilities within each of the different CVSS score ranges
# (4.0 – 4.9, 5.0 – 5.9, 6.0 – 6.9, 7.0 – 7.9, 8.0 – 8.9, 9.0 – 9.9, and 10.0).
# The colors for CVSS Scores are
# orange for medium severity with a rating of 4.0 – 6.9,
# red for high severities that have a rating of 7.0 – 9.9,
# and purple for critical severities with a rating of 10.0. 


# Sometimes Nessus could report a vuln as having 0 exploits or only private ones.
# But if you know about a specific vuln and have found an exploit for that (like for MS07-010) 
# from the NSA leak .. search in the source this 'if ($pluginName =~ /'
# and add the name of the nessus plugin in the regexp and add the info of the exploit accordingly


use HTML::Entities;
use URI::Escape;
use Data::Dumper;

# use warnings;
# use strict;

my $report = $ARGV[0];

if (!$ARGV[1]) {
	$cvss_risk_limit = "7.5";
}
else {
	$cvss_risk_limit = $ARGV[1];
	if ($cvss_risk_limit !~ /^[0-9.]+$/i) {
		&help;
	}
}

if (!$ARGV[2]) {
	$show_exploit_name = 'yes';
}
else {
	$show_exploit_name = $ARGV[2];
	if ($show_exploit_name !~ /yes|no/i) {
		&help;
	}
}
# if (!$ARGV[3]) {
# 	$all_finding = 'no';
# }
# else {
# 	$show_exploit_name = $ARGV[2];
# 	if ($show_exploit_name !~ /yes|no/i) {
# 		&help;
# 	}
# }

$include_solution = 'yes';
$include_exploited  = 'yes';
$include_synopsis = 'yes';
$include_findings_cve_bid_only = 'yes';

if ((!$report)||($report !~ /\.nessus$/)) {
	&help;
}

my $out_file = '';
if ($report =~ /^(.+)\.nessus/) {
	$out_file = $1."_vuln_softwate_table.html";
}


%finding = {};
%risk = {};

%critical_vulns = ();
%vulns_grouped_by_number_critical = ();
%high_vulns = ();
%vulns_grouped_by_number_high = ();
%exploitable_vulns_public = ();
%exploitable_vulns_private = ();
%exploitable_vulns_public_grouped_by_number = ();
%exploitable_vulns_private_grouped_by_number = ();


open(F, '<', $report);

my $content = '';
while (my $a = <F>) {
	$content .= $a;
}

$content =~ s/<ReportHost/\n\n\n\n<ReportHost/g;

@hosts_content = split /\n\n\n\n/, $content;

my $host_content = '';		
my $ip = '';	
foreach my $bit(@hosts_content) {

	if ($bit =~ /<ReportHost name="([^"]+)"/) {
		$ip = $1;

	}

	my $cbit = $bit;
	$cbit =~ s/<ReportItem/\n\n\n\n<ReportItem/g;
	@host_contents = split /\n\n\n\n/, $cbit;

	foreach my $hbit(@host_contents) {
		my $port = '';
		my $protocol = '';
		my $pluginName = '';
		
		if ($hbit =~ /<ReportItem pluginFamily="[^"]+" pluginID="[^"]+" pluginName="([^"]+)" port="([^"]+)" protocol="([^"]+)" severity="4" svc_name="cifs">/) {
			
			$port = $2;
			$protocol = $3;
			$pluginName = decode_entities($1);
		}
		if ($hbit =~ /<ReportItem port="([^"]+)" svc_name="[^"]+" protocol="([^"]+)" severity="[^"]+" pluginID="[^"]+" pluginName="([^"]+)" pluginFamily="[^"]+">/) {
			
			$port = $1;
			$protocol = $2;
			$pluginName = decode_entities($3);
		}
		$pluginName =~ s/\(remote check\)//;
		$pluginName =~ s/\(uncredentialed check\)//;
		
		my $service = $ip." (".$protocol."/".$port.")";


		my $cves = '';
		while ($hbit =~ /<cve>([^<]+)<\/cve>/g) {
			$cves .= $1.",";
		}
		$cves =~ s/,$//;

		my $bids = '';
		while ($hbit =~ /<bid>([^<]+)/g) {
			$bids .= $1.",";
		}
		$bids =~ s/,$//;

		my $expl_avail_public = 'No';

		my $synopsis = '';
		if ($include_synopsis eq 'yes') {
			if ($hbit =~ /<synopsis>([^<]+)</) {
				$synopsis = decode_entities($1);
			}
		}
		

		if ($hbit =~ /<exploit_available>true/) {
			if (($hbit =~ /<exploit_framework_metasploit>true/)||($hbit =~ /<exploited_by_nessus>true/)) {
				$expl_avail_public = 'Yes';
			}
			else {
				$expl_avail_public = 'Private';
			}
		}

		my $msf_name = '';
		if ($show_exploit_name eq 'yes') {
			if ($hbit =~ /<metasploit_name>([^<]+)/) {
				$msf_name = '<a href="https://www.google.com.au/search?q='.uri_escape($1).'">('.$1.')</a>';
			}			
		}

		my $solution = '';
		if ($include_solution eq 'yes') {
			if ($hbit =~ /<solution>([^<]+)/) {
				$solution = $1;
			}
		}

		$cvss_base_score = '';
		if ($hbit =~ /<cvss_base_score>([^<]+)/) {
			$cvss_base_score = $1;
		}
		if ($cvss_base_score < $cvss_risk_limit) {
			next;
		}
		my $risk_text = '';
		if ($hbit =~ /<risk_factor>([^<]+)/) {
			$risk_text = $1;
		}

		$risk{$cvss_base_score}{$pluginName} = 'x';

		if ($include_findings_cve_bid_only eq 'yes') {
			if ((length($bids) > 0)||(length($cves) > 0)) {print "....\n";
				if (!exists $finding{$pluginName}) {
	
	
					$finding{$pluginName}{'exploits'} = $expl_avail_public;
					$finding{$pluginName}{'cve'} = $cves;
					$finding{$pluginName}{'services'} = $service;
					$finding{$pluginName}{'risk'} = $cvss_base_score;
					$finding{$pluginName}{'risk_text'} = $risk_text;
					$finding{$pluginName}{'msf_name'} = $msf_name;
					if ($include_solution eq 'yes') {
						$finding{$pluginName}{'solution'} = $solution;
					}
					if ($include_synopsis eq 'yes') {
						$finding{$pluginName}{'synopsis'} = $synopsis;
					}
	
	
				}
				else {
					$finding{$pluginName}{'services'} .= ', '.$service;
				}
	
				if ($pluginName =~ /MS17-010/) {
					$expl_avail_public = 'Yes';
					$finding{$pluginName}{'exploits'} = 'Yes';
					$finding{$pluginName}{'msf_name'} = '<a href="https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit">Eternalblue-Doublepulsar</a>';
				}
				
				if (($risk_text eq 'Critical')||($risk_text eq 'High')) {
					if ($risk_text eq 'Critical') {
						
						if (!exists $critical_vulns{$ip}) {
							$critical_vulns{$ip} = 1;
						}
						else {
							my $p = $critical_vulns{$ip};
							$critical_vulns{$ip} = $p+1;
						}
	
					}
					elsif ($risk_text eq 'High') {
						if (!exists $high_vulns{$ip}) {
							$high_vulns{$ip} = 1;
						}
						else {
							my $p = $high_vulns{$ip};
							$high_vulns{$ip} = $p+1;
						}
	
					}
					if ($expl_avail_public eq 'Yes') {print "## ip: $ip - PN: $pluginName\n";
						if (!exists $exploitable_vulns_public{$ip}) {
							$exploitable_vulns_public{$ip} = 1;
						}
						else {
							my $p = $exploitable_vulns_public{$ip};
							$exploitable_vulns_public{$ip} = $p+1;
						}					
					}
					elsif ($expl_avail_public eq 'Private') {
						if (!exists $exploitable_vulns_private{$ip}) {
							$exploitable_vulns_private{$ip} = 1;
						}
						else {
							my $p = $exploitable_vulns_private{$ip};
							$exploitable_vulns_private{$ip} = $p+1;
						}
					}
	
				}

			}
		}

	}

}

my @final_plugins_sorted = ();
for $key ( sort {$b<=>$a} keys %risk) {

	my @plugin_names_sorted = ();
	my @plugin_names = ();
	while ( my ($keyy, $valuee) = each(%risk) ) {
		
		if ($keyy eq $key) {
		 	while ( my ($keyyy, $valueer) = each(%$valuee) ) {
				push(@plugin_names,$keyyy);

			}			
		}


	}
	#my @plugin_names_sorted = sort @plugin_names;
	@plugin_names_sorted = sort @plugin_names;
	foreach my $pp(@plugin_names_sorted) {
		push(@final_plugins_sorted, $pp);
	}
}

while (my ($key, $value) = each(%critical_vulns)) {
	# $key is the IP, $value is the count number
	if (!exists $vulns_grouped_by_number_critical{$value}) {
		$vulns_grouped_by_number_critical{$value} = $key;
	}
	else {
		my $p = $vulns_grouped_by_number_critical{$value};
		$vulns_grouped_by_number_critical{$value} = $p.",".$key;
	}
}

while (my ($key, $value) = each(%high_vulns)) {
	print "key: $key - value: $value\n";
	# $key is the IP, $value is the count number
	if (!exists $vulns_grouped_by_number_high{$value}) {
		$vulns_grouped_by_number_high{$value} = $key;
	}
	else {
		my $p = $vulns_grouped_by_number_high{$value};
		$vulns_grouped_by_number_high{$value} = $p.",".$key;
	}
}

while (my ($key, $value) = each(%exploitable_vulns_public)) {
	# $key is the IP, $value is the count number
	if (!exists $exploitable_vulns_public_grouped_by_number{$value}) {
		$exploitable_vulns_public_grouped_by_number{$value} = $key;
	}
	else {
		my $p = $exploitable_vulns_public_grouped_by_number{$value};
		$exploitable_vulns_public_grouped_by_number{$value} = $p.",".$key;
	}

}
while (my ($key, $value) = each(%exploitable_vulns_private)) {
	# $key is the IP, $value is the count number
	if (!exists $exploitable_vulns_private_grouped_by_number{$value}) {
		$exploitable_vulns_private_grouped_by_number{$value} = $key;
	}
	else {
		my $p = $exploitable_vulns_private_grouped_by_number{$value};
		$exploitable_vulns_private_grouped_by_number{$value} = $p.",".$key;
	}
}


print "\n\n\n";

my $css_style = '<style type="text/css">

table {
	padding: 0;
	border: 0;
	border-spacing: 0px;
	border-collapse:collapse;
}

tr {
	padding: 0;
	border: 0;
	border-spacing: 0px;
}

td {
	border-width: 1px 1px 1px 1px;
	border-style: solid;
	border-color: black;
	border-spacing: 0px;
	padding: 0px;
}

.header {
	background-color: #808080;
	color: white;
}

</style>';

my $html = '<html><head><title>'.$out_file.'</title>'.$css_style.'</head><body>Reference to CVSS scoring guide: https://www.first.org/cvss/v2/guide</br>
the risk score in the table is the CVSS 2.0 base score</br></br></br></br>
<table>
<tr class="header"><td>Item</td><td>Risk (CVSS2)</td><td>Name</td><td>#Services</td><td>#CVEs</td><td>Exploits</td></tr>';

my $number = 0;
foreach my $p(@final_plugins_sorted) {
	# print "$p\n";
	
	while ( my ($a, $b) = each(%finding) ) {
		if ($a eq $p) {
			$number++;
			$html .= '<tr>';
			my $services_c = 1;
			while ($finding{$a}{'services'} =~ /,/g) {
				$services_c++;
			}
			my $cve_c = 1;
			while ($finding{$a}{'cve'} =~ /,/g) {
				$cve_c++;
			}

			my $risk_color = '';
			if ($finding{$a}{'risk_text'} eq 'Critical') {
				$risk_color = '#eb42f4';
			}
			elsif ($finding{$a}{'risk_text'} eq 'High') {
				$risk_color = '#f72e2e';
			}
			elsif ($finding{$a}{'risk_text'} eq 'Medium') {
				$risk_color = '#f9a01b';
			}
			$html .= '<td>'.$number.'</td>';
			$html .= '<td style="background-color: '.$risk_color.'">'.$finding{$a}{'risk'}.'</td>';
			$html .= '<td>'.$a.'</td>';
			$html .= '<td>'.$services_c.'</td>';
			$html .= '<td>'.$cve_c.'</td>';
			$html .= '<td>'.$finding{$a}{'exploits'}.'</td>';

			print "\n\n".$finding{$a}{'risk'}." - name: $a\n";
			print "\t\texploits:".$finding{$a}{'exploits'}."\n";
			print "\t\tservices: ".$services_c."\n";
			print "\t\tcves: ".$cve_c."\n";
			$html .= '</tr>';
		}
	}
}

$html .= '</table></br></br></br></br></br><table style="border:1px solid black;border-collapse:collapse;"><tr class="header"><td>Risk (CVSS2)</td><td>Name</td><td>Services</td><td>CVEs</td><td>Exploits</td>';

if ($include_exploited eq 'yes') {
	$html .= '<td>Exploited</td>';
}
if ($include_synopsis eq 'yes') {
	$html .= '<td>Synopsis</td>';
}
if ($include_solution eq 'yes') {
	$html .= '<td>Solution</td>';
}
$html .= '</tr>';

foreach my $p(@final_plugins_sorted) {
	while ( my ($a, $b) = each(%finding) ) {
		if ($a eq $p) {
			$html .= '<tr>';

			my $services = $finding{$a}{'services'};
			$services =~ s/,/<\/br>/g;
			my $cvesz = $finding{$a}{'cve'};
			my $cve_urls_st = '';
			while ($cvesz =~ /([^,]+)/g) {
				$cve_urls_st .= '<a href="https://www.cvedetails.com/cve/'.$1.'/">'.$1.'</a></br>';
			}

			my $risk_color = '';
			if ($finding{$a}{'risk_text'} eq 'Critical') {
				$risk_color = '#eb42f4';
			}
			elsif ($finding{$a}{'risk_text'} eq 'High') {
				$risk_color = '#f72e2e';
			}
			elsif ($finding{$a}{'risk_text'} eq 'Medium') {
				$risk_color = '#f9a01b';
			}

			my $msf_str = '';
			if (length($finding{$a}{'msf_name'}) > 0) {
				$msf_str = '</br>'.$finding{$a}{'msf_name'};
			}

			$html .= '<td style="background-color: '.$risk_color.'">'.$finding{$a}{'risk'}.'</td>';
			$html .= '<td>'.$a.'</td>';
			$html .= '<td>'.$services.'</td>';
			$html .= '<td>'.$cve_urls_st.'</td>';
			$html .= '<td>'.$finding{$a}{'exploits'}.$msf_str.'</td>';


			if ($include_exploited eq 'yes') {
				$html .= '<td>No</td>';
			}
			if ($include_synopsis eq 'yes') {
				$html .= '<td>'.$finding{$a}{'synopsis'}.'</td>';
			}
			if ($include_solution eq 'yes') {
				$html .= '<td>'.$finding{$a}{'solution'}.'</td>';
			}

			print "\n\n".$finding{$a}{'risk'}." - name: $a\n";
			print "\t\texploits:".$finding{$a}{'exploits'}."\n";
			print "\t\tservices: ".$finding{$a}{'services'}."\n";
			print "\t\tcves: ".$finding{$a}{'cve'}."\n";
			print "\t\trisk: ".$finding{$a}{'risk_text'}."\n";
			print "\t\tMSF: ".$finding{$a}{'msf_name'}."\n";
			$html .= '</tr>';
		}
	}
}
$html .= '</table>';



# </br></br></br></br></br><table style="border:1px solid black;border-collapse:collapse;">
# <tr class="header"><td>



 print Dumper(%vulns_grouped_by_number_critical);
print "\n\nSystems most affected by Critical vulnerabilities (Grouped, Desc sorted)\n\n";
if (keys(%vulns_grouped_by_number_critical) > 0) {
	for $key ( sort {$b<=>$a} keys %vulns_grouped_by_number_critical) {
		my $v = $vulns_grouped_by_number_critical{$key};
		print "$key Critical-risk affecting ".count_items($v)." systems:\n\t$v\n";
	}	
}
else {
	print "\t0 systems found affected by critical-risk vulnerabilities.\n";
}


print "\n\nSystems most affected by High vulnerabilities (Grouped, Desc sorted)\n\n";
if (keys(%vulns_grouped_by_number_high) > 0) {
	for $key ( sort {$b<=>$a} keys %vulns_grouped_by_number_high) {
		my $v = $vulns_grouped_by_number_high{$key};
		print "$key High-risk affecting ".count_items($v)." systems:\n\t$v\n";
	}	
}
else {
	print "\t0 systems found affected by high-risk vulnerabilities.\n";
}

print "\n\nMost exploitable systems (Very likley - Public exploits available)\n";
if (keys(%exploitable_vulns_public_grouped_by_number) > 0) {
	for $key ( sort {$b<=>$a} keys %exploitable_vulns_public_grouped_by_number) {
		my $v = $exploitable_vulns_public_grouped_by_number{$key};
		print "\n$key vulnerability with public exploit code affecting ".count_items($v)." systems:\n\t$v\n";
	}	
}
else {
	print "\t0 systems found affected by vulnerabilities with public exploit code.\n";
}


print "\n\nMost exploitable systems (Less likley - Only private exploits available)\n";
if (keys(%exploitable_vulns_private_grouped_by_number) > 0) {
	for $key ( sort {$b<=>$a} keys %exploitable_vulns_private_grouped_by_number) {
		my $v = $exploitable_vulns_private_grouped_by_number{$key};
		print "\n$key vulnerability with private exploit code affecting ".count_items($v)." systems:\n\t$v\n";
	}	
}
else {
	print "\t0 systems found affected by vulnerabilities with private exploit code.\n";	
}

print "\n\n\n";

# Systems more at risk

# system con + public expl



$html .= '</body></html>';


open(OUT, '>', $out_file);
print OUT $html;
close(OUT);
`open $out_file`;

sub help {
	print "\nPlease supply the .nessus report\n\tUsage:   perl $0 <report.nessus> <riskLimitCVSS> <ShowExplName>".
			"\n\tExample: perl $0 report.nessus 7.5 yes\n\n";exit;
}

sub count_items() {
	my $str = $_[0];
	my $c = 1;
	if (length($str) > 0) {
		if ($str !~ /,/) {
			return(1);
		}
		else {
			while ($str =~ /,/g) {
				$c++;
			}
			return($c);
		}
	}
	else {
		return(0);
	}
}

#EOF
