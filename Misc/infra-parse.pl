#!/usr/bin/perl

## infra-parse.pl - HTTPx CSV output parser and analyzer
## Written in January 2023 to work on a big Synack target with caffeine
## This is a polished version of the original (no italian swearing, etc)
## by @osiryszzz
##
## Parses HTTPx CSV output and provides:
##   - Statistics grouped by IP, status code, content length, content type, title, banner, CDN
##   - Search functionality across all fields
##   - Unique URL deduplication based on response characteristics
##
## Input CSV format (from HTTPx with specific flags):
##   "BaseURL","Status","Length","Type","Title","Banner","IP","CDN","Tech","Redirect"

use strict;
use warnings;
use Data::Dumper;
use Term::ANSIColor;
use Getopt::Long;
use File::Path qw(make_path);

# ============================================================================
# Configuration
# ============================================================================

my $VERSION = "2.0.0";

# ============================================================================
# Global Variables
# ============================================================================

my %urls = ();
my %ips = ();
my %banners = ();
my %titles = ();
my %responses_length = ();
my %status_codes = ();
my %content_types = ();
my %cdns = ();
my %techs = ();
my %stats = ();
my %processed_by_type = ();

my %unique_by_ip = ();
my %unique_by_sc = ();
my %unique_by_cl = ();
my %unique_by_ct = ();
my %unique_by_t = ();
my %unique_by_b = ();
my %unique_final_urls = ();

my $tot_urls = 0;
my $time = time();

# ============================================================================
# Argument Parsing
# ============================================================================

my $input_file;
my $output_dir;
my $action = 'stats';
my $obj_type;
my $search_term;
my $show_help = 0;
my $show_version = 0;
my $no_color = 0;
my $quiet = 0;

# Parse command line - support both old positional and new flag-based
if (@ARGV && $ARGV[0] !~ /^-/) {
	# Positional argument mode for backwards compatibility
	$output_dir = shift @ARGV if (@ARGV >= 2 && $ARGV[1] !~ /^(stats|show|search)$/i);
	$input_file = shift @ARGV;
	$action = shift @ARGV // 'stats';
	$obj_type = shift @ARGV;
	$search_term = shift @ARGV;
} else {
	GetOptions(
		'input|i=s'    => \$input_file,
		'output|o=s'   => \$output_dir,
		'action|a=s'   => \$action,
		'type|t=s'     => \$obj_type,
		'search|s=s'   => \$search_term,
		'help|h'       => \$show_help,
		'version|v'    => \$show_version,
		'no-color'     => \$no_color,
		'quiet|q'      => \$quiet,
	) or help("Invalid options");
}

# Handle help/version
help() if $show_help;
version() if $show_version;

# Validate required arguments
help("Missing input file") unless $input_file;

# Set default output directory
$output_dir //= "$ENV{HOME}/.infra-parse";

# Validate action
$action = lc($action);
unless ($action =~ /^(stats|show|search)$/) {
	help("Invalid action '$action' - valid options are: stats, show, search");
}

# Validate search parameters
if ($action eq 'search') {
	help("Search requires object type (-t) and search term (-s)") unless ($obj_type && $search_term);
	$obj_type = normalize_obj_type($obj_type);
	help("Invalid object type '$obj_type'") unless $obj_type;
}

# ============================================================================
# File Setup
# ============================================================================

# Create output directory if needed
unless (-d $output_dir) {
	make_path($output_dir) or help("Cannot create output directory '$output_dir': $!");
}

# Open input file
open(my $INPUT, '<', $input_file) or help("Cannot open input file '$input_file': $!");

# Setup output files
my $out_ips = "$output_dir/ips_urls_$time.txt";
my $out_sc  = "$output_dir/sc_urls_$time.txt";
my $out_cl  = "$output_dir/cl_urls_$time.txt";
my $out_ct  = "$output_dir/ct_urls_$time.txt";
my $out_t   = "$output_dir/t_urls_$time.txt";
my $out_b   = "$output_dir/b_urls_$time.txt";
my $out_cdn = "$output_dir/cdn_urls_$time.txt";
my $out_tech = "$output_dir/tech_urls_$time.txt";

open(my $OI,   '>', $out_ips)  or help("Cannot create file '$out_ips': $!");
open(my $OSC,  '>', $out_sc)   or help("Cannot create file '$out_sc': $!");
open(my $OCL,  '>', $out_cl)   or help("Cannot create file '$out_cl': $!");
open(my $OCT,  '>', $out_ct)   or help("Cannot create file '$out_ct': $!");
open(my $OT,   '>', $out_t)    or help("Cannot create file '$out_t': $!");
open(my $OB,   '>', $out_b)    or help("Cannot create file '$out_b': $!");
open(my $OCDN, '>', $out_cdn)  or help("Cannot create file '$out_cdn': $!");
open(my $OTECH,'>', $out_tech) or help("Cannot create file '$out_tech': $!");

# ============================================================================
# Main Execution
# ============================================================================

parse_input($INPUT);
close($INPUT);

aggregate_data($action, {
	OI   => $OI,
	OSC  => $OSC,
	OCL  => $OCL,
	OCT  => $OCT,
	OT   => $OT,
	OB   => $OB,
	OCDN => $OCDN,
	OTECH => $OTECH,
});

# Close output files
close($OI);
close($OSC);
close($OCL);
close($OCT);
close($OT);
close($OB);
close($OCDN);
close($OTECH);

if ($action eq 'search') {
	search_data($obj_type, $search_term);
} elsif ($action eq 'stats') {
	show_stats();
}

# Print unique URL summary if not quiet
unless ($quiet) {
	my $tot_unique = keys(%unique_final_urls);
	info("\nTotal unique URLs (by response characteristics): $tot_unique");
}

exit(0);

# ============================================================================
# Subroutines
# ============================================================================

sub parse_input {
	my ($fh) = @_;
	my $line_num = 0;
	
	while (my $line = <$fh>) {
		$line_num++;
		chomp($line);
		
		# Skip header row
		next if $line_num == 1 && $line =~ /^"BaseURL"/i;
		
		# Skip empty lines
		next unless length($line) > 0;
		
		# Parse CSV line
		# Format: "BaseURL","Status","Length","Type","Title","Banner","IP","CDN","Tech","Redirect"
		if ($line =~ /^"([^"]+)","([^"]+)","([^"]+)","([^"]*)","([^"]*)","([^"]*)","([^"]*)","([^"]*)","([^"]*)","([^"]*)"/) {
			my ($url, $status, $length, $content_type, $title, $banner, $ip, $cdn, $tech, $redir) = 
			   ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);
			
			# Extract hostname from URL
			my $hostname = '';
			if ($url =~ /^https?:\/\/([^:\/]+)/) {
				$hostname = $1;
			}
			
			# Extract numeric status code
			my $status_code = '';
			if ($status =~ /^([0-9]+)/) {
				$status_code = $1;
			}
			
			# Aggregate by various attributes
			push(@{ $status_codes{$status_code}{'urls'} }, $url);
			push(@{ $responses_length{$length}{'urls'} }, $url);
			push(@{ $ips{$ip}{'urls'} }, $url) if length($ip) > 0;
			push(@{ $content_types{$content_type}{'urls'} }, $url) if length($content_type) > 0;
			push(@{ $titles{$title}{'urls'} }, $url) if length($title) > 0;
			push(@{ $banners{$banner}{'urls'} }, $url) if length($banner) > 0;
			push(@{ $cdns{$cdn}{'urls'} }, $url) if length($cdn) > 0;
			push(@{ $techs{$tech}{'urls'} }, $url) if length($tech) > 0;
			
			# Store URL details (deduplicated)
			if (!exists $urls{$url}) {
				$tot_urls++;
				$urls{$url} = {
					ip       => $ip,
					sc       => $status,
					cl       => $length,
					ct       => $content_type,
					t        => $title,
					b        => $banner,
					cdn      => $cdn,
					tech     => $tech,
					redir    => $redir,
					hostname => $hostname,
				};
			}
		}
		# Also try parsing 7-field format for backwards compatibility
		elsif ($line =~ /^"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]+)"/) {
			my ($url, $status, $length, $content_type, $title, $banner, $ip) = 
			   ($1, $2, $3, $4, $5, $6, $7);
			
			my $hostname = '';
			if ($url =~ /^https?:\/\/([^:\/]+)/) {
				$hostname = $1;
			}
			
			my $status_code = '';
			if ($status =~ /^([0-9]+)/) {
				$status_code = $1;
			}
			
			push(@{ $status_codes{$status_code}{'urls'} }, $url);
			push(@{ $responses_length{$length}{'urls'} }, $url);
			push(@{ $ips{$ip}{'urls'} }, $url) if length($ip) > 0;
			push(@{ $content_types{$content_type}{'urls'} }, $url) if length($content_type) > 0;
			push(@{ $titles{$title}{'urls'} }, $url) if length($title) > 0;
			push(@{ $banners{$banner}{'urls'} }, $url) if length($banner) > 0;
			
			if (!exists $urls{$url}) {
				$tot_urls++;
				$urls{$url} = {
					ip       => $ip,
					sc       => $status,
					cl       => $length,
					ct       => $content_type,
					t        => $title,
					b        => $banner,
					cdn      => '',
					tech     => '',
					redir    => '',
					hostname => $hostname,
				};
			}
		}
	}
	
	info("Parsed $tot_urls unique URLs from input") unless $quiet;
}


sub aggregate_data {
	my ($op, $fh) = @_;
	
	# Aggregate by IP
	my $count_url = 0;
	print colored("\nURLs by IP:\n", 'bold') if $op eq 'show';
	foreach my $ip (sort keys %ips) {
		print "IP: $ip\n" if $op eq 'show';
		my @urls_by_ip = @{ $ips{$ip}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_ip) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OI}} "$ip - $u\n";
			$count_url++;
		}
		$stats{'IPs'}{$ip} = $c;
	}
	$processed_by_type{'IPs'} = $count_url;
	print "\nURLs by IP: $count_url processed out of $tot_urls\n\n" if $op eq 'show';
	
	# Aggregate by status code
	$count_url = 0;
	print colored("\nURLs by status code:\n", 'bold') if $op eq 'show';
	foreach my $st_code (sort { $a <=> $b } keys %status_codes) {
		print "Status Code: $st_code\n" if $op eq 'show';
		my @urls_by_sc = @{ $status_codes{$st_code}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_sc) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OSC}} "$st_code - $u\n";
			$count_url++;
			
			# Track unique combinations
			my $u_title = $urls{$u}{'t'};
			my $u_cl = $urls{$u}{'cl'};
			
			if (!exists $unique_by_sc{'t'}{$u_title}) {
				$unique_by_sc{'t'}{$u_title} = 1;
				$unique_final_urls{$u} = "" unless exists $unique_final_urls{$u};
			}
			if (!exists $unique_by_sc{'cl'}{$u_cl}) {
				$unique_by_sc{'cl'}{$u_cl} = 1;
				$unique_final_urls{$u} = "" unless exists $unique_final_urls{$u};
			}
		}
		$stats{'sc'}{$st_code} = $c;
	}
	$processed_by_type{'sc'} = $count_url;
	print "\nURLs by status code: $count_url processed\n\n" if $op eq 'show';
	
	# Aggregate by content length
	$count_url = 0;
	print colored("\nURLs by content length:\n", 'bold') if $op eq 'show';
	foreach my $clength (sort { $a <=> $b } keys %responses_length) {
		print "Content Length: $clength\n" if $op eq 'show';
		my @urls_by_cl = @{ $responses_length{$clength}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_cl) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OCL}} "$clength - $u\n";
			$count_url++;
			
			my $u_title = $urls{$u}{'t'};
			my $u_sc = $urls{$u}{'sc'};
			
			if (!exists $unique_by_cl{'t'}{$u_title}) {
				$unique_by_cl{'t'}{$u_title} = 1;
				$unique_final_urls{$u} = "" unless exists $unique_final_urls{$u};
			}
			if (!exists $unique_by_cl{'sc'}{$u_sc}) {
				$unique_by_cl{'sc'}{$u_sc} = 1;
				$unique_final_urls{$u} = "" unless exists $unique_final_urls{$u};
			}
		}
		$stats{'cl'}{$clength} = $c;
	}
	$processed_by_type{'cl'} = $count_url;
	print "\nURLs by content length: $count_url processed\n\n" if $op eq 'show';
	
	# Aggregate by content type
	$count_url = 0;
	print colored("\nURLs by content type:\n", 'bold') if $op eq 'show';
	foreach my $ctype (sort keys %content_types) {
		print "Content Type: $ctype\n" if $op eq 'show';
		my @urls_by_ct = @{ $content_types{$ctype}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_ct) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OCT}} "$ctype - $u\n";
			$count_url++;
		}
		$stats{'ct'}{$ctype} = $c;
	}
	$processed_by_type{'ct'} = $count_url;
	print "\nURLs by content type: $count_url processed\n\n" if $op eq 'show';
	
	# Aggregate by title
	$count_url = 0;
	print colored("\nURLs by title:\n", 'bold') if $op eq 'show';
	foreach my $title (sort keys %titles) {
		print "Title: $title\n" if $op eq 'show';
		my @urls_by_t = @{ $titles{$title}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_t) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OT}} "$title - $u\n";
			$count_url++;
			
			my $u_sc = $urls{$u}{'sc'};
			my $u_cl = $urls{$u}{'cl'};
			
			if (!exists $unique_by_t{'sc'}{$u_sc}) {
				$unique_by_t{'sc'}{$u_sc} = 1;
				$unique_final_urls{$u} = "" unless exists $unique_final_urls{$u};
			}
			if (!exists $unique_by_t{'cl'}{$u_cl}) {
				$unique_by_t{'cl'}{$u_cl} = 1;
				$unique_final_urls{$u} = "" unless exists $unique_final_urls{$u};
			}
		}
		$stats{'t'}{$title} = $c;
	}
	$processed_by_type{'t'} = $count_url;
	print "\nURLs by title: $count_url processed\n\n" if $op eq 'show';
	
	# Aggregate by banner
	$count_url = 0;
	print colored("\nURLs by banner:\n", 'bold') if $op eq 'show';
	foreach my $banner (sort keys %banners) {
		print "Banner: $banner\n" if $op eq 'show';
		my @urls_by_b = @{ $banners{$banner}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_b) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OB}} "$banner - $u\n";
			$count_url++;
		}
		$stats{'banner'}{$banner} = $c;
	}
	$processed_by_type{'b'} = $count_url;
	print "\nURLs by banner: $count_url processed\n\n" if $op eq 'show';
	
	# Aggregate by CDN
	$count_url = 0;
	print colored("\nURLs by CDN:\n", 'bold') if $op eq 'show';
	foreach my $cdn (sort keys %cdns) {
		print "CDN: $cdn\n" if $op eq 'show';
		my @urls_by_cdn = @{ $cdns{$cdn}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_cdn) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OCDN}} "$cdn - $u\n";
			$count_url++;
		}
		$stats{'cdn'}{$cdn} = $c;
	}
	$processed_by_type{'cdn'} = $count_url;
	print "\nURLs by CDN: $count_url processed\n\n" if $op eq 'show';
	
	# Aggregate by Tech
	$count_url = 0;
	print colored("\nURLs by Tech:\n", 'bold') if $op eq 'show';
	foreach my $tech (sort keys %techs) {
		print "Tech: $tech\n" if $op eq 'show';
		my @urls_by_tech = @{ $techs{$tech}{'urls'} };
		my $c = 0;
		for my $u (@urls_by_tech) {
			$c++;
			print "\t$u\n" if $op eq 'show';
			print {$fh->{OTECH}} "$tech - $u\n";
			$count_url++;
		}
		$stats{'tech'}{$tech} = $c;
	}
	$processed_by_type{'tech'} = $count_url;
	print "\nURLs by Tech: $count_url processed\n\n" if $op eq 'show';
}


sub search_data {
	my ($param, $term) = @_;
	
	my %search_map = (
		'IPs'   => \%ips,
		'sc'    => \%status_codes,
		'cl'    => \%responses_length,
		'ct'    => \%content_types,
		't'     => \%titles,
		'b'     => \%banners,
		'cdn'   => \%cdns,
		'tech'  => \%techs,
	);
	
	my %param_names = (
		'IPs'   => 'IP',
		'sc'    => 'status code',
		'cl'    => 'content length',
		'ct'    => 'content type',
		't'     => 'title',
		'b'     => 'banner',
		'cdn'   => 'CDN',
		'tech'  => 'technology',
	);
	
	my $hash_ref = $search_map{$param};
	my $param_name = $param_names{$param};
	
	if (exists $hash_ref->{$term}) {
		print colored("\nURLs with $param_name '$term':\n", 'bold green');
		my @matching_urls = @{ $hash_ref->{$term}{'urls'} };
		for my $u (@matching_urls) {
			print "\t$u\n";
		}
		print "\nTotal: " . scalar(@matching_urls) . " URLs\n";
	} else {
		print colored("\nNo URLs found with $param_name '$term'\n", 'yellow');
	}
}


sub show_stats {
	my %most_vhosts = ();
	my %most_stcodes = ();
	my %most_length = ();
	my %most_ctype = ();
	my %most_titles = ();
	my %most_banners = ();
	my %most_cdns = ();
	my %most_techs = ();
	
	# Invert the stats hashes to group by count
	while (my ($key, $value) = each(%{ $stats{'IPs'} })) {
		push(@{ $most_vhosts{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'sc'} })) {
		push(@{ $most_stcodes{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'cl'} })) {
		push(@{ $most_length{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'ct'} })) {
		push(@{ $most_ctype{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'t'} })) {
		push(@{ $most_titles{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'banner'} })) {
		push(@{ $most_banners{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'cdn'} })) {
		push(@{ $most_cdns{$value} }, $key);
	}
	while (my ($key, $value) = each(%{ $stats{'tech'} })) {
		push(@{ $most_techs{$value} }, $key);
	}
	
	# Print statistics
	print_stat_section("URLs by IP (VHOSTs)", \%most_vhosts, "IPs being A records to [%d] URLs:");
	print_stat_section("URLs by Status Code", \%most_stcodes, "%d URLs returned status code(s):");
	print_stat_section("URLs by Content Length", \%most_length, "%d URLs had content length(s):");
	print_stat_section("URLs by Content Type", \%most_ctype, "%d URLs had content type(s):");
	print_stat_section("URLs by Title", \%most_titles, "%d URLs had title(s):");
	print_stat_section("URLs by Banner", \%most_banners, "%d URLs had banner(s):");
	print_stat_section("URLs by CDN", \%most_cdns, "%d URLs behind CDN(s):") if keys(%most_cdns);
	print_stat_section("URLs by Technology", \%most_techs, "%d URLs using technology:") if keys(%most_techs);
}


sub print_stat_section {
	my ($title, $hash_ref, $format) = @_;
	
	print colored("\n\n-- $title --\n\n", 'bold cyan');
	foreach my $count (sort { $b <=> $a } keys(%$hash_ref)) {
		my @items = @{ $hash_ref->{$count} };
		printf($format . "\n", $count);
		foreach my $item (@items) {
			print "\t$item\n";
		}
	}
}


sub normalize_obj_type {
	my ($type) = @_;
	$type = lc($type);
	
	my %type_map = (
		'ip'      => 'IPs',
		'ips'     => 'IPs',
		'sc'      => 'sc',
		'status'  => 'sc',
		'cl'      => 'cl',
		'length'  => 'cl',
		'ct'      => 'ct',
		'type'    => 'ct',
		't'       => 't',
		'title'   => 't',
		'b'       => 'b',
		'banner'  => 'b',
		'cdn'     => 'cdn',
		'tech'    => 'tech',
	);
	
	return $type_map{$type} // undef;
}


sub info {
	my ($msg) = @_;
	print colored("[*] ", 'blue') . "$msg\n" unless $no_color;
	print "[*] $msg\n" if $no_color;
}


sub version {
	print "infra-parse.pl v$VERSION\n";
	exit(0);
}


sub help {
	my $error = shift;
	
	my $usage = qq{
infra-parse.pl v$VERSION - HTTPx CSV Output Parser & Analyzer
@osiryszzz

USAGE:
    perl infra-parse.pl [OPTIONS] <input.csv> [action] [obj_type] [search_term]
    perl infra-parse.pl -i <input.csv> -a <action> [-t <obj_type>] [-s <search_term>]

ACTIONS:
    stats   Show summary statistics grouped by each attribute (default)
    show    Display all URLs organized by each object type
    search  Find URLs matching a specific attribute value

OBJECT TYPES (for search):
    ip      IP address
    sc      HTTP status code
    cl      Content length
    ct      Content type
    t       Page title
    b       Server banner
    cdn     CDN provider
    tech    Detected technology

OPTIONS:
    -i, --input <file>      Input CSV file (required)
    -o, --output <dir>      Output directory (default: ~/.infra-parse)
    -a, --action <action>   Action to perform: stats, show, search
    -t, --type <type>       Object type for search
    -s, --search <term>     Search term
    -q, --quiet             Suppress informational messages
    --no-color              Disable colored output
    -h, --help              Show this help message
    -v, --version           Show version

EXAMPLES:
    # Show statistics (default action)
    perl infra-parse.pl input.csv
    
    # Show all URLs grouped by attribute
    perl infra-parse.pl input.csv show
    
    # Search for URLs with specific IP
    perl infra-parse.pl input.csv search ip 192.168.1.1
    
    # Search for URLs with specific title
    perl infra-parse.pl input.csv search t 'Welcome Page'
    
    # Search for 200 status codes
    perl infra-parse.pl input.csv search sc 200
    
    # Search for Cloudflare CDN
    perl infra-parse.pl input.csv search cdn cloudflare
    
    # Specify custom output directory
    perl infra-parse.pl -o /tmp/results -i input.csv
    
    # Using long options
    perl infra-parse.pl --input input.csv --action search --type ip --search 10.0.0.1

INPUT FORMAT:
    CSV file from HTTPx with the following columns:
    "BaseURL","Status","Length","Type","Title","Banner","IP","CDN","Tech","Redirect"
    
    Generate with HTTPx flags:
    httpx -title -content-length -status-code -content-type -cdn -tech-detect \\
          -location -web-server -follow-redirects -random-agent -ip -csv

OUTPUT FILES:
    Output directory contains categorized URL lists:
    - ips_urls_<timestamp>.txt     URLs grouped by IP
    - sc_urls_<timestamp>.txt      URLs grouped by status code
    - cl_urls_<timestamp>.txt      URLs grouped by content length
    - ct_urls_<timestamp>.txt      URLs grouped by content type
    - t_urls_<timestamp>.txt       URLs grouped by title
    - b_urls_<timestamp>.txt       URLs grouped by banner
    - cdn_urls_<timestamp>.txt     URLs grouped by CDN
    - tech_urls_<timestamp>.txt    URLs grouped by technology
};

	if ($error) {
		print STDERR colored("\nError: $error\n", 'bold red');
	}
	print $usage;
	exit($error ? 1 : 0);
}

__END__

=head1 NAME

infra-parse.pl - HTTPx CSV output parser and infrastructure analyzer

=head1 SYNOPSIS

    perl infra-parse.pl <input.csv> [stats|show|search] [obj_type] [search_term]

=head1 DESCRIPTION

Parses HTTPx CSV output and provides aggregation, statistics, and search
capabilities across multiple response attributes. Useful for analyzing
large-scale HTTP reconnaissance data and identifying patterns in web
infrastructure.

=head1 FEATURES

=over 4

=item * Groups URLs by IP, status code, content length, content type, title, banner, CDN, and technology

=item * Identifies unique URLs based on response characteristics

=item * Generates separate output files for each attribute type

=item * Supports both positional and flag-based argument parsing

=item * Backwards compatible with 7-field CSV format

=back

=head1 AUTHOR

@osiryszzz

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut