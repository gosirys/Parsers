#!/usr/bin/perl

# yGAudit
# Small utility to find user supplied input (GET,POST,COOKIE,SERVER)
# vars inside CMS and Web Apps. 
# by Osirys - y-osirys.com - osirys[at]autistici[dot]org

use File::Find;

my $obj 				= $ARGV[0];
my $log_file			= 0;
my $file_name_pattern 	= "\.php\$";
my $debug_mode 		= 0; # 1 -> yes, 2 -> 0
my $log_file			= 0; # 1 -> yes ($dir.txt), 2 -> 0
my $match_count		= 0;
my(@matched,@alerts);

@match_patternsz = (
				"\\\$HTTP_(GET|POST|COOKIE)_VARS\\[([^\\[\\]]*)\\]",
				"\\\$_(GET|POST|COOKIE)\\[([^\\[\\]]*)\\]",
				"(\\\$HTTP_SERVER_VARS|\\\$_SERVER)\\[([\"']*)(HTTP_USER_AGENT|REFERER)([\"']*)\\]"
			   );#print $match_patterns[2]."\n";exit;


@match_patterns = (
				"\\\$HTTP_(GET|POST|COOKIE)_VARS",
				"\\\$_(GET|POST|COOKIE)",
				"(\\\$HTTP_SERVER_VARS|\\\$_SERVER)"
			   );#print $match_patterns[2]."\n";exit;


banner();
check_conf();
find(\&scan, $obj);
end();

sub scan {
	my $file = $File::Find::name;
	#print "scanno $file\n";
	if (!-f $file) {
		#print "non è file .. returno\n";
		if ($debug_mode == 1) {
			push(@alerts,"[!] $file -> Is not a file, next.\n");
		}
		return;
	}
	if ($file !~ /$file_name_pattern/) {
		#print "non è file con estensione voluta: $file\n";
		if ($debug_mode == 1) {
			push(@alerts,"[!] $file -> Is not a file with a liked extension.\n");
		}
		return;
	}

	if (!open(F,'<',$file)) {
		if ($debug_mode == 1) {
			push(@alerts,"[-] $file -> Unable to open.\n");
		}
		return;
	}
	#print "analizzo $file\n";
	my $line_numb = 0;
	while (my $line = <F>) {
		$line_numb++;
		my($a,$b,$c) = ($match_patterns[0],$match_patterns[1],$match_patterns[2]);
		if ($line =~ /$a|$b|$c/i) {
			$match_count++;
			my $tmp_line = $line;
			$tmp_line =~ s/^\s+//g;
			my $mphr = "[".$match_count."] ".$file."[".$line_numb."] ->\n    ".$tmp_line."\n";
			push(@matched,$mphr);
		}
	}
	close(F);
}

sub check_conf() {
	if (!$obj) {
		die "\n[-] Missing argument !\n".
		    "    Usage: perl $0 absolute_path_to_scan\n".
		    "    Ex:    perl $0 /home/osirys/data/web/phpBB/\n\n";
	}
	if (length($file_name_pattern) < 1) {
		die "\n[-] Bad file name pattern match, check configuration !\n\n";
	}
	if ($log_file == 1) {
		$log_fname = $obj;
		$log_fname =~ s/^(.*)(\/)([^\/]+)(\/*)$/$3\_yrep.txt/;
		if (!open(FL,'>',$log_fname)) {
			die "\n[-] Unable to create log file: $log_fname !\n\n";
		}
	}
}

sub banner() {
	&yprint(
			"\n---------------------------\n".
			"    yGAudit - by Osirys\n".
			"        y-osirys.com\n".
			"---------------------------\n\n"
		 );
}

sub yprint() {
	my $w = $_[0];
	my $opt = $_[1];
	if ($log_file == 1) {
		print FL $w;
	}
	print $w;
}

sub end() {
	if (length(@matched) > 0) {
		&yprint("[+] Total matches: ".scalar(@matched)." . Listing: \n\n");
		foreach my $m(@matched) {
			&yprint($m);
		}
		&yprint("\n\n");
	}
	if (($debug_mode == 1)&&(length(@alerts) > 0)) {
		&yprint("[!-] Alerts and Errors: ".scalar(@alerts)." . Listing: \n\n");
		foreach my $a(@alerts) {
			&yprint($a);
		}
	}
	if ($log_file == 1) {
		close(FL);
	}
}

#EOF