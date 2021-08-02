#!/usr/bin/perl

# This script parses a Nmap's XML output file, grabs all software versions and searches for vulns/exploits on cvedetails
# coded sometime in November 2013


use LWP::UserAgent;
use Getopt::Long;


my($log_file,$input_file,$file_st,$loop_stop,$all_vulns,$div_report_C,$tot_search_completed,$html,
   $foot,$tr_str,$INPUT,$INPUT_R,$OUTPUT,$OUTPUT_R,$version_null_skip,$ch1222,$good_choice_,$xml_str,
   $host_nmap_from,$requests_performed_block_count) = ('','',0,0,0,0,0,'','','',0,0,0,0,1,'',0,'',0,0);

@partial_matches, @no_matches, @partial_urls, @no_urls, @vuln_to_go;
my $found_vulns_yes_mm = 0;
GetOptions('out=s' =>  \$log_file, 'in=s' =>  \$input_file);

# --in=0:file.xml 	-> input is file.xml, will skip softwares without version
# --in=1:file.xml 	-> input is file.xml, will process softwares without version, version will be * (any)
# --in=file.xml 	-> input is file.xml, will process softwares without version, version will be * (any)
#
# --out=all:company	-> output name will be company, with all formats: txt, html, mindmap with vulnerabilities
# --out=def:company	-> output name will be company, with default formats: txt and html
# --out=mmv:company	-> output name will be company, only mindmap format with vulnerabilities
# --out=mm:company	-> output name will be company, only mindmap format without vulnerabilities though

# $option_ch stores the kind of output [4,3,2,1]



# WORKS: perl yvm.txt --in=a.xml --out=mm:xxx
# : perl yvm.txt --in=a.xml --out=mmv:xxx

if ((length($input_file) > 0)&&(length($log_file) < 1)) {
	#errore
	
}

ybanner();

my $option_ch;
if (length($log_file) > 0) {
	if ($log_file =~ /^(all|def|mmv|mm|null):(.+)$/) {
		my($a,$b) = ($1,$2);
		$log_file =~ s/^.+$/$b/;#print "ororo: $log_file\n";
		
		if ($log_file =~ /\.mm|\.html|\.txt/) {
			$log_file =~ s/\.mm//;
			$log_file =~ s/\.txt//;
			$log_file =~ s/\.html//;
		}
		
		
		if ($a eq 'all') {
			# all : txt,html,mindmap+vulns
			$option_ch = 4;
			test_create_logs($option_ch);
		}
		elsif ($a eq 'def') {
			# only txt and html rep
			$option_ch = 3;
			test_create_logs($option_ch);
		}
		elsif ($a eq 'mmv') {
			# only mindmap but with vulns inside
			$option_ch = 2;
			test_create_logs($option_ch);
		}
		elsif ($a eq 'mm') {
			# only mindmap but with no vulns
			$option_ch = 1;
			test_create_logs($option_ch);
		}#print "loggggg: $b\n";
		elsif ($a eq 'null') {
			# only mindmap but with no vulns
			$option_ch = 4;#print "nullzzz\n\n";
			test_create_logs($option_ch);
		}
		
		
	}
	else {
		yprint("\n[-] Syntax Error: bad log file syntax!\n\n");
	}
}

if (length($input_file) > 0) {#print "oppopop\n";
	if ($input_file =~ /^(1|0):(.+)$/) {
		my($a,$b) = ($1,$2);
		if ($a == 1) {
			$version_null_skip = 0;
		}
		$input_file = $b;
	}
	
	$INPUT = 1;
	if ($input_file =~ /\.gnmap$|\.nmap$|\.xml$|\.mm$/) {
		if (!open INPUT_F, '<', $input_file) {
			yprint("[-] The input file provided could not be opened !\n    $!\n\n");
			exit(0);
		}
		else {
			my $input_file_content = '';
			while (my $a = <INPUT_F>) {
				$a =~ s/\n//g;
				if ($a =~ /<host /) {
					$c++;
					$a =~ s/<host /\n\n<host /;
				}
				if ($a =~ /<\/host>/) {
					$a =~ s/<\/host>/<\/host>\n\n/;
				}
				$input_file_content .= $a;
			}

			if ($input_file =~ /\.xml$/) {#print "uuuuu\n";
				&analyze_xml($input_file_content,$option_ch);#print $ret."\n";exit;
				#print "uuuuu\n";
				#exit;
				#$xml_str = $ret;

			}

		}
	}
}

if ($INPUT != 1) {#print "ppp\n";
	while (($good_choice_ != 1)||($loop_stop != 1)) {
		&remove_arrays();
		yprint("[] Software Name: ");
		chomp(my $software_name = <STDIN>);
		yprint("[] Software Version: ");
		chomp(my $software_version = <STDIN>);
		if (length($software_name) < 1 || length($software_version) < 1) {
			yprint("[-] Bad input(s) ! Return !\n");
			$good_choice_ = 0;
		}
		else {
			&search_start($software_name,$software_version);
		}
	}
}	

sub search_start() {
	my($software,$version) = @_;
	$div_report_C++;
	yprint("Software : $software\nVersion : $version\n\n",1);
	$good_choice_ = 1;
	if ($version =~ /\*/) {
		$all_vulns = 1;
	}
	if ($ddsoftware =~ /apache|tomcat|iis|php|asp|cfm|coldfusion/i) {
		# The choosen Software is known, does't have to be searched.
		# Go straight away to its own vulnerabilities page
		known_prod($software_name,$software_version,$all_vulns);
	}
	else {
		my $psearch_found = 0;
		&remove_arrays();
		$psearch_found = product_search($software,$version);
		if ($psearch_found =~ /V>(.+)/) {#print "\n\nPsearchfound: $psearch_found\n\n";
			my $soft = $1;#print "soft: $soft\n\n";
			&remove_arrays();#print "soft: $soft - vers: $version\n\n";
			$psearch_found = vendor_search($soft,$version);
			if ($psearch_found == 0) {
				yprint("\n[-] $software-$soft not found by searching by Product neither by Vendor. Bad Luck !!\n\n");
			}
		}
		else {
			if ($psearch_found == 2) {
				yprint("\n[-] None of the vulnerabilities passed the user Filter(s) !\n");
			}
			elsif ($psearch_found == 0) {
				yprint("\n[-] F*ucked !!\n\n");
			}
			elsif ($psearch_found == 'R') {
				yprint("\n[-] Session quitted. Back to Main Menu() :\n\n");
			}
		}
	}
}

sub product_search() {
	my($software_namee,$software_version,$from_vendor,$countzz) = (@_);
	
	#if (length($countzz) < 1) {
		
	#}
	
	my $software_name = encode($software_namee);
	my $version_listing_page;

	my $link = 'http://www.cvedetails.com/product-search.php?vendor_id=0&search='.$software_name;
	#print "link: $link\n";
	my $res  = request($link);
	
	#print "Res:\n\n$res\n\nLength: ".length($res)."\n\n";
	
	if (($res !~ /Could not find any products matching the search criteria/)&&($res =~ /<a href="http:\/\/www\.cvedetails\.com\/product\//)) {
		# Positive Match.
		# Determine now how many products have been found. In case of many, print them all
		# to let the user pick the more appropriate one
		my $product_found_count = 0;
		while ($res =~ /<a href="http:\/\/www\.cvedetails\.com\/product\//g) {
			$product_found_count++;
		}
		if ($product_found_count == 1) {
			
			my $regxp = "<a href=\"([^\"]+)\" title=\"Product Details \">([^<]+)<\/a>([^<]*)<\/td>([^<]*)<td>([^<]*)<([^>]+)>".
						"([^<]+)<\/a>([^<]*)<\/td>([^<]*)<td class=\"num\">([^<]*)<a href=\"\/vulnerability-list\/([^\"]+)\" ".
						"title=\"See all vulnerabilities of this product\">([^<]+)<\/a>";

			if ($res =~ /$regxp/) {
				my($product_link,$product_name,$product_vendor,$product_vuln_page,$product_tot_vulns) = ($1,$2,$7,$11,$12);
			
				$product_name 		=~ s/^([^a-zA-Z]+)([a-zA-Z\s]+)([^a-zA-Z]+)/$2/;
				$product_vendor 	=~ s/^([^a-zA-Z]+)([a-zA-Z\s]+)([^a-zA-Z]+)/$2/;
				$product_vuln_page 	= 'http://www.cvedetails.com/vulnerability-list/'.$product_vuln_page;
				$product_tot_vulns 	=~ s/^([^0-9]+)([0-9]+)([^0-9]+)/$2/;
			
			
				yprint(	"[!] I found one product matching your supplied string:\n    Product Name: $product_name\n    ".
						"Vendor Name: $product_vendor\n    Total Vulnerabilites: $product_tot_vulns\n\n[+] Please press 1 to confirm, anything else to search by Vendor name\n\n".
						"[+] Choice: ");
				chomp(my $ch = <STDIN>);
				if ($ch != 1) {
					#return('V');
					return('V>'.$software_namee);
				}
			
				if ($all_vulns == 1) {
					my $back = vuln_listing($product_vuln_page,$software_version,$product_name);
					return($back = fun_return($back));
				}
				else {
					my $res = request($product_link);
					if ($res =~ /<a href="\/version-list\/([^"]+)"/) {
						$version_listing_page = 'http://www.cvedetails.com/version-list/'.$1;
						my $back = version_listing($version_listing_page,$software_version,$product_name);
						return($back = fun_return($back));
					}
				}
				
			}
			else {
				#### ! Debug : Problem with REGEXP $regxp in matching products
			}
		}
		elsif ($product_found_count > 1) {
			my $back_tovendor = 0;
			my $regxp = "<a href=\"([^\"]+)\" title=\"Product Details \">([^<]+)<\/a>([^<]*)<\/td>([^<]*)<td>([^<]*)<([^>]+)>".
						"([^<]+)<\/a>([^<]*)<\/td>([^<]*)<td class=\"num\">([^<]*)<a href=\"\/vulnerability-list\/([^\"]+)\" ".
						"title=\"See all vulnerabilities of this product\">([^<]+)<\/a>";
			
			
			yprint("[+] Found several matches. Listing them all :\n\n");
			my @lol = ();
			#print $res."\n\n\n\n";
			while ($res =~ /$regxp/g) {
				
				my($product_link,$product_name,$product_vendor,$product_vuln_page,$product_tot_vulns) = ($1,$2,$7,$11,$12);
				
				$product_name 		=~ s/^([^a-zA-Z]+)([a-zA-Z\s]+)([^a-zA-Z]+)/$2/;
				$product_vendor  	=~ s/^([^a-zA-Z]+)([a-zA-Z\s]+)([^a-zA-Z]+)/$2/;
				$product_vuln_page 	= 'http://www.cvedetails.com/vulnerability-list/'.$product_vuln_page;
				$product_tot_vulns 	=~ s/^([^0-9]+)([0-9]+)([^0-9]+)/$2/;
				
				my $str = 'AA'.$product_link.'BB'.$product_name.'CC'.$product_vendor.'DD'.$product_vuln_page.'EE'.$product_tot_vulns;
				push(@lol, $str);
			}
			
			my $count = 0;
			foreach my $e(@lol) {
				$e =~ /^AA(.+)BB(.+)CC(.+)DD(.+)EE(.+)$/;
				my($a,$b,$c) = ($2,$3,$5);
				
				my $str = 	"Product#: ".$count."\n    Product Name: ".$a."\n    Vendor Name: ".$b.
							"\n    Vulnerabilities: ".$c."\n\n";
				yprint($str);
				$count++;
			}
			
			yprint("[+] Type now the number related to the product you were looking for OR type 'V' to search by Vendor name\n\n");
			my $good_pcode = 0;
			my $pcode;
			while (($good_pcode == 0)&&($back_tovendor == 0)) {
				yprint("[+] Product: ");
				chomp($pcode = <STDIN>);
				if ($pcode eq 'V') {
					$back_tovendor = 1;
				}
				else {
					if (($pcode > $#lol)||($pcode < 0)) {
						return;
					}
					else {
						$good_pcode = 1;
					}
				}
			}
			if ($back_tovendor == 1) {
				#return('V');
				return('V>'.$software_namee);
			}

			my $str = $lol[$pcode];
			$str =~ /^AA(.+)BB(.+)CC(.+)DD(.+)EE(.+)$/;
			my($a1,$b1,$c1,$d1,$e1) = ($1,$2,$3,$4,$5);
	
			if ($all_vulns == 1) {
				#### GO TO $singles_values[2] --> go straigh away to to vuln listing (all version)
				my $back = vuln_listing($d1,$software_version,$b1);
				return($back = fun_return($back));
			}
			else {
				my $link = $a1;#print $link;
				my $res = request($link);
				if ($res =~ /<a href="\/version-list\/([^"]+)"/) {
					$version_listing_page = 'http://www.cvedetails.com/version-list/'.$1;
				}
				my $back = version_listing($version_listing_page,$software_version,$b1);
				return($back = fun_return($back));
			}	
		}	
	}
	else {
		#print "trovato una sega ...\n\n";
		if ($countzz != 1) {#print "prima volta ...\n\n";
			if ($software_namee =~ /^([^ ]+) ([^ ]+)/) {#print" mandiamo di nuovo:\n";
				&product_search($1,$software_version,'',1);
			}
		}
		else {
			# Negative Match. Return
			#print "hjsjdhjdhjd\n";
			return('V>'.$software_namee);
			#return('V');
		}
	}
}




sub vendor_search() {
	my($vendor_namee,$software_version,$countzz) = @_;#print "\n\nfffff: $vendor_namee - VER: $software_version\n\n";
	my $vendor_name = encode($vendor_namee);
	my $link = 'http://www.cvedetails.com/vendor-search.php?search='.$vendor_name;
	#print "linksss: $link\n\n";
	my $res  = request($link);
			
	if (($res !~ /Could not find any vendors/)&&($res =~ /Number of Products/)) {
	
		# $1 -> Product List Page
		# $2 -> Vendor Name found
		# $3 -> Total products for this vendor
		# $4 -> All vuln list page
		# $5 -> Number of vulnerabilities
	
		my $regexp = 	'<td class="num">[\\s]*<a href="([^"]+)" title="See products of ([^"]+)">'.
						'[\\s]*([0-9]+)[\\s]*<\/a>[\\s]*<\/td>[\\s]*<td class="num">[\\s]*<a href'.
						'="([^"]+)" title="All vulnerabilities[^"]+">[\\s]*([0-9]+)[\\s]*<\/a>';
		
		
		my $vendor_found_count = 0;
		while ($res =~ /<a href="http:\/\/www\.cvedetails\.com\/vendor\//g) {
			$vendor_found_count++;
		}
		
		my $good_vendor_string = '';
		my @vendors_list;

		while ($res =~ /$regexp/g) {
			my($product_list_page,$vendor_namef,$total_products,$vuln_list_page,$total_vulns) = ($1,$2,$3,$4,$5);
			$product_list_page   = 'http://www.cvedetails.com'.$product_list_page;
			$vuln_list_page = 'http://www.cvedetails.com'.$vuln_list_page;
				
			my $vend_str = 'AA'.$product_list_page.'BB'.$vendor_namef.'CC'.$total_products.'DD'.$vuln_list_page.'EE'.$total_vulns;
			push(@vendors_list,$vend_str);#print "vend_str $vend_str\n";
		}
		
		if (scalar(@vendors_list) > 1) {
			yprint("[+] Found several matches. Listing them all :\n\n");
				
			my $count = 0;
			foreach my $e(@vendors_list) {

				$e =~ /^AA(.+)BB(.+)CC(.+)DD(.+)EE(.+)$/;
				my($a,$b,$c) = ($2,$3,$5);
				my $str = 	"Vendor#: ".$count."\n    Vendor Name: ".$a."\n    Total Products: ".$b.
							"\n    Tot Vulnerabilities: ".$c."\n\n";
				yprint($str);
				$count++;
			}
				
			yprint("[+] Type now the number related to the vendor OR type 'R' to return.\n\n");
			my $good_pcode = 0;
			my $back_tomenu = 0;
			while (($good_pcode == 0)&&($back_tomenu == 0)) {
				yprint("[+] Vendor: ");
				chomp(my $pcode = <STDIN>);
				if ($pcode eq 'R') {
					$back_tomenu = 1;
				}
				else {
					if (($pcode > $#vendors_list)||($pcode < 0)) {
						return;
					}
					else {
						$good_pcode = 1;
					}
				}
			}
			if ($back_tomenu == 1) {#print "xx\n";
				return('R');
			}

			my $str = $vendors_list[$pcode];
			$good_vendor_string = $str;
			$go = 1;
		}
		else {
			my $str = $vendors_list[0];
			$str =~ /^AA(.+)BB(.+)CC(.+)DD(.+)EE(.+)$/;
			my($a,$b,$c) = ($2,$3,$5);
			
			yprint(	"[!] I found one vendor matching your supplied string:\n    Vendor Name: $a\n    ".
					"Tot Products: $b\n    Total Product Vulns: $c\n\n[+] Please press 1 to confirm, 0 to avoid (will return to main menu)\n\n".
					"[+] Choice: ");
			chomp(my $ch = <STDIN>);
			if ($ch == 1) {
				$go = 1;
				$good_vendor_string = $str;
			}
			else {
				return('R');
			}
		}
		
				
		if ($go == 1) {
			$good_vendor_string =~ /^AA(.+)BB(.+)CC(.+)DD(.+)EE(.+)$/;
			my($product_list_page,$b1,$c1,$d1,$e1) = ($1,$2,$3,$4,$5);#print "$a1 $b1 $c1 $d1\n";
			my @products_found_byvendor;
					#print $product_list_page."\n";#exit;
			my $res = request($product_list_page);
			$res = &get_no_ofitems($res,'Ven',$product_list_page);
						
			# $1 -> product page(absolute)	
			# $2 -> product name		
			# $3 -> vuln list of product (relative)
			# $4 -> total vuln that affect the product
			
			my $regexp = 	'<a href="([^"]+)" title="Product Details ">([^<]+)<\/a>[\\s]*<\/td>'.
							'[\\s]*<td>[\\s]*<a[^<]+<\/a>[\\s]*<\/td>[\\s]*<td class="num">[\\s]'.
							'*<a href="([^"]+)"[^>]+>[\\s]*([0-9]+)[\\s]*<\/a>';
						
			my $count = 0;
					
			while ($res =~ /$regexp/g) {
				my($product_page,$product_name,$prod_vuln_list_page,$tot_vuln) = ($1,$2,$3,$4);
				$tot_vuln =~ s/^([^a-zA-Z0-9]+)([A-Za-z0-9.-\s]+)/$2/g;
				$tot_vuln =~ s/([\s]{2,})//;
				$prod_vuln_list_page = 'http://www.cvedetails.com'.$prod_vuln_list_page;
				my $str = 	"Product#: ".$count."\n    Product Name: ".$product_name."\n    Vulnerabilities: ".$tot_vuln."\n\n";
				yprint($str);
				
				my $strr = 'AA'.$product_page.'BB'.$prod_vuln_list_page.'CC'.$product_name;
				push(@products_found_byvendor,$strr);
				$count++;
			}	
						
			yprint("[+] Type now the number related to the product you were looking for OR type 'R' to return.\n\n");
			my $good_pcode = 0;
			my $pcode = '';
			my $go_backk = 0;
			while (($good_pcode == 0)&&($go_backk == 0)) {
				yprint("[+] Product: ");
				chomp($pcode = <STDIN>);
				if ($pcode eq 'R') {
					$go_backk = 1;
				}
				else {
					if (($pcode > $#products_found_byvendor)||($pcode < 0)) {
						return;
					}
					else {
						$good_pcode = 1;
					}
				}
			}
			if ($go_backk == 1) {#print "xx\n";
				return('R');
			}
			my $string = $products_found_byvendor[$pcode];
			$string =~ /^AA(.+)BB(.+)CC(.+)$/;
			my($a,$b,$c) = ($1,$2,$3);
			if ($all_vulns == 1) {
				my $back = vuln_listing($b,$software_version,$c);
				return($back = &fun_return($back));
			}
			else {
				my $version_listing_page;
				my $res = request($a);
				if ($res =~ /<a href="\/version-list\/([^"]+)"/) {
					$version_listing_page = 'http://www.cvedetails.com/version-list/'.$1;
				}
				my $back = version_listing($version_listing_page,$software_version,$c);
				return($back = &fun_return($back));
			}	
		}
		#else {
		#	return(0);
		#}
	}
	else {
		# Did not find any vendor. Fail Fail Fail
		
		#print "trovato una sega ...\n\n";
		if ($countzz != 1) {#print "prima volta ...\n\n";
			if ($vendor_namee =~ /^([^ ]+) ([^ ]+)/) {#print" mandiamo di nuovo:\n";
				&vendor_search($1,$software_version,'',1);
			}
		}
		else {
		
		
			return(0);
		}
	}
}

#http://www.cvedetails.com/version-list/546/942/1/Lyris-List-Manager.html
#http://www.cvedetails.com/vulnerability-list.php?vendor=Lyris&product=List%20Manager&product_id=942&vendor_id=546

sub known_prod() {
	my($software,$software_version,$all_vulns) = @_;
	my $back = 0;
	if ($software =~ /apache/i) {
		if ($all_vulns == 1) {
			$back = vuln_listing('http://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-66/Apache-Http-Server.html',$software_version);
		}
		else {
			$back = version_listing('http://www.cvedetails.com/product/66/Apache-Http-Server.html?vendor_id=45',$software_version);
		}
	}
	elsif ($software =~ /tomcat/i) {
		if ($all_vulns == 1) {
			$back = vuln_listing('http://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-887/Apache-Tomcat.html',$software_version);
		}
		else {
			$back = version_listing('http://www.cvedetails.com/product/887/Apache-Tomcat.html?vendor_id=45',$software_version);
		}			
	}		
	elsif ($software =~ /iis/i) {
		if ($all_vulns == 1) {
			$back = vuln_listing('http://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-3436/Microsoft-IIS.html',$software_version);
		}
		else {
			$back = version_listing('http://www.cvedetails.com/product/3436/Microsoft-IIS.html?vendor_id=26',$software_version);
		}	
	}
	elsif ($software =~ /php/i) {
		if ($all_vulns == 1) {
			$back = vuln_listing('http://www.cvedetails.com/vulnerability-list/vendor_id-74/product_id-128/PHP-PHP.html',$software_version);
		}
		else {
			$back = version_listing('http://www.cvedetails.com/product/128/PHP-PHP.html?vendor_id=74',$software_version);
		}
	}
	elsif ($software =~ /asp/i) {
		if ($all_vulns == 1) {
			$back = vuln_listing('http://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-3091/Microsoft-Asp.net.html',$software_version);
		}
		else {
			$back = version_listing('http://www.cvedetails.com/product/3091/Microsoft-Asp.net.html?vendor_id=26',$software_version);
		}
	}
	elsif ($software =~ /cfm|coldfusion/i) {
		if ($all_vulns == 1) {
			$back = vuln_listing('http://www.cvedetails.com/vulnerability-list/vendor_id-53/product_id-8739/Adobe-Coldfusion.html',$software_version);
		}
		else {
			$back = version_listing('http://www.cvedetails.com/product/8739/Adobe-Coldfusion.html?vendor_id=53',$software_version);
		}
	}
	if ($back == 1) {
		return(1);
	}
	elsif ($back == 2) {
		#yprint("\n[-] None of the vulnerabilities passed the user Filter(s) !\n");
		return(2);
	}
	else {
		return(0);
	}
}

sub version_listing() {
	my($link,$version_to_match,$product_name_) = @_;#print "\n\n$link\n\n";#print "UUUUUUUUUUUUUUUUUUUUUUUUUUU"
	my $res = request($link);#print "\ndentro a vuln listig: versione da cercare: $version_to_match\n";
	my $toexcludefromversion;
	my $match_found = 0;
	my $version_found;

	# This cvedetails it's so bad to be regexped due to the table system, needs all this code.
	# think about me coding it :S lol rulez.
	
	my $regexp = 	'<td>([^<]+)<\/td>([^<]*)<td>([^<]+)<\/td>([^<]*)<td>([^<]+)<\/td>([^<]*)<td>'.
					'([^<]+)<\/td>([^<]*)<td class="num">([^<]+)<\/td>([^<]*)<td>([^<]*)<a href='.
					'"([^"]+)" title="([^"]+)">Details<\/a>([^<]*)<a href="\/vulnerability-lis'.
					't\/([^\/]+)\/([^\/]+)\/([^\/]+)\/([^"]+)"';
	
	# $1    Version 						++
	# $2    shit between tags
	# $3    Language						++
	# $4    shit between tags
	# $5    Update							++
	# $6    shit between tags
	# $7    Edition							++
	# $8    shit between tags
	# $9    Number of Vulnerabilities		++
	# $10   shit between tags
	# $11   shit between tags
	# $12   href
	# $13   href title
	# $14   shit between tags
	# $15   Link pt1						++
	# $16   Link pt2						++
	# $17   Link pt3						++
	# $18   Link pt4						++
	
	my $final;

	$res = get_no_ofitems($res,'Ve',$link);
	$res =~ s/^TOT_RES[0-9]+TOT_RES//;
	my $version_found_count = 0;
	my @string_back = ();
	while (($res =~ /$regexp/g)&&($match_found != 1)) {
		my($a,$b,$c,$d,$e,$f,$g,$h,$i) = ($1,$3,$5,$7,$9,$15,$16,$17,$18);
		$version_found_count++;
		my(@tmp_array,@last_array) = ();
		push(@tmp_array,$a,$b,$c,$d,$e,$f,$g,$h,$i);
		my $str = '';
		foreach my $e(@tmp_array) {
			my $copy = $e;
			if ($copy =~ /[a-zA-Z0-9.-]+/) {
				$copy =~ s/^([^a-zA-Z0-9]+)([A-Za-z0-9.-\s]+)/$2/g;
				$copy =~ s/([\s]{2,})//;
			}
			else {
				$copy = 'NULL';
			}
			$str .= $copy.'%%%%%';
		}
		$str =~ s/%%%%%$//;
#print "ststs: STR: $str\n\n";
		$match_found = try_match($str,$version_to_match);

		if ($match_found == 1) {
			$final = $str;
		}
	}
	
	my $itemp = 'R';
	my $goodness = 0;
	my $itempp = 0;
	if ($match_found != 1) {
		## No 100 % Match.
		if (scalar(@partial_matches) > 0) {#print "hsjhsjs!!!!!!!!!^76767678678678^&!*^!&^!&*!^&!*^!&*^!&*!^&*!^&*!\n";foreach my $i(@partial_matches) { print "$i\n";}
			yprint(	"[!] I could not find any 100 % match with the given input. However ..\n".
					"    I found a total of ".scalar(@partial_matches)." partial matches.\n    Partial matches for wanted product:\n".
					"        $product_name_/$version_to_match\n :\n");
			$itemp = display_all('Partial');		
		}
		else {
			$itemp = display_all('All');
			#print "itempo ritornato: $itemp\n\n";
			$itempp = 1;
		}
	}
	else {
		$goodness = 1;
	}



	if (($itemp ne 'R')||($goodness == 1)) {#print "ACAB\n\n";
		my $link;
		if ($goodness == 1) {
			$final =~ /%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)$/;
			my($urlpt1,$urlpt2,$urlpt3,$urlpt4) = ($1,$2,$3,$4);
			$link = 'http://www.cvedetails.com/vulnerability-list/'.$1.'/'.$2.'/'.$3.'/'.$4;
		}
		else {
			if ($itemp =~ /^P(.+)$/i) {
				$link = $partial_urls[$1];
			}
			elsif ($itemp =~ /^N(.+)$/i) {
				$link = $no_urls[$1];
			}
			$link =~ /-([0-9.]+)\.html$/;
			$version_to_match = $1;
			
		}
		my $back = vuln_listing($link,$version_to_match,$product_name_);
		return($back = &fun_return($back));
	}
	else {#print "54674567546457654764756754654765475467456574654765475647546754645n\nitemp: $itemp itempp: $itempp\n\n";
	
		if (($itemp eq 'R')&&($itempp == 1)) {#print "ritorno R\n";
			return('R');
		}
		else {
			return(0);
		}
	
	
	
		# Fuck. Nothing, end of jokes. No match, or bad user supplied info. I'm tired now to handle thousand
		# of exceptions, if you didn't supply the right stuff, put more attention next time, and this software
		# won't be here in this else else else else else condition :-) 
		#return(0);
	}
}

sub display_all() {
	my($opt) = @_;
	my $item;
	
	if ($opt eq 'All') {
		yprint(	"[-] I could not find any match. Actions:\n    T - Shows all versions, you'll pick the".
		 		" more appropriate one\n    E - Exit\n    R - go back\n\n[+] Choice: ");#print "\n\nXuX\n\n";
		
		chomp(my $act = <STDIN>);
		if ($act eq 'E') {
			exit(0);
		}
		elsif ($act eq 'R') {#print "returning .....\n";
			return('R');
		}
		elsif ($act eq 'T') {
			my $act;
			my $no_count = 0;
			my $p_count = 0;
			if (scalar(@partial_matches) > 0) {
				foreach my $p(@partial_matches) {
					yprint("\nPartial #P".$p_count." :\n".$p);
					$p_count++;
				}
			}
			foreach my $n(@no_matches) {
				yprint("\nNo Match #N".$no_count." :\n".$n);
				$no_count++;
			}
			
			yprint(	"\n[+] Choose now the version you think is more appropriate (#code), or :\n".
					"    E - exit\n".
					"    R - go back\n\n");

			my $good_ch = 0;
			my $act;
			while (($good_ch == 0)&&($back_tomenu == 0)) {
				yprint("[+] Choice: ");
				chomp($act = <STDIN>);
				if (($act eq 'E')||($act eq 'R')||(($act =~ /^(P|N)([0-9]+)$/i)||($act =~ /^#(P|N)([0-9]+)$/i))) {
					$good_ch = 1;
				}
			}
			if ($act eq 'E') {
				&safe_close();
			}
			elsif ($act eq 'R') {
				return;
			}
			elsif (($act =~ /^(P|N)([0-9]+)$/i)||($act =~ /^#(P|N)([0-9]+)$/i)) {
				$item = $1.$2;
				return($item);
			}	
		}
	}
	elsif ($opt eq 'Partial') {
		my $part_count = 0;
		foreach my $p(@partial_matches) {
			yprint("\nPartial #P".$part_count." :\n".$p);
			$part_count++;
		}
		yprint(	"\n[+] Choose now the version you think is more appropriate (Partial #code), or :\n".
				"    E - exit\n    T - displays ALL versions (even the < 50 % match)\n    R - go back\n\n");
						
		my $good_ch = 0;
		my $act;
		while (($good_ch == 0)&&($back_tomenu == 0)) {
			yprint("[+] Choice: ");
			chomp($act = <STDIN>);
			if (($act eq 'E')||($act eq 'T')||($act eq 'R')||(($act =~ /^P([0-9]+)$/i)||($act =~ /^#P([0-9]+)$/i))) {
				$good_ch = 1;
			}
		}
			
		if ($act eq 'E') {
			&safe_close();
		}
		elsif ($act eq 'T') {
			&display_all('All');
		}
		elsif ($act eq 'R') {
			return;
		}
		elsif (($act =~ /^P([0-9]+)$/i)||($act =~ /^#P([0-9]+)$/i)) {
			$item = $1;
			return('P'.$item);
		}
		
	}	
}

sub get_no_ofitems() {
	my($res,$pagek,$link) = @_;
	my $total_results;
	my @vuln_page_links;
	my $pgcount = 0;
	my $tot_pages;
	
	if ($pagek eq 'Ve') {
		$res =~ /mber of versions found = ([0-9]+)/;
		$total_results = $1;
	}
	elsif ($pagek eq 'Vu') {
		$res =~ /mber of vulnerabilities : <b>([0-9]+)<\/b>/;
		$total_results = $1;
	}
	elsif ($pagek eq 'Ven') {#print "hjdhdjhdjdhjdhjdd\n";
		$res =~ /mber of products found = ([0-9]+)/;
		$total_results = $1;#print "total results: $total_results\n";
	}
	
	
	my $tot_pages_tmp = $total_results/50;
	if ($tot_pages_tmp =~ /^0/) {#print "tot pagine: 1\n";
		$tot_pages = 1;
	}
	else {
		if ($tot_pages_tmp !~ /\./) {
			$tot_pages = $tot_pages_tmp;
		}
		else {
			$tot_pages_tmp =~ s/^([0-9]+)\.([0-9]+)$/$1/;
			$tot_pages = $tot_pages_tmp + 1;
		}
		#print " tot pagine: $tot_pages\n";
	}
	
	if ($tot_pages > 1) {
		if ($pagek eq 'Ve') {
			$link =~ s/version-list\/([0-9]+)\/([0-9]+)\/([0-9]+)\/(.+)$/version-list\/$1\/$2\/::PAGE::\/$4/;
			$res = '';
			while ($pgcount < $tot_pages) {
				$pgcount++;
				my $link_ = $link;
				$link_ =~ s/::PAGE::/$pgcount/;
				$res .= request($link_);
			}
		}
		elsif ($pagek eq 'Vu') {
			while ($res =~ /<a[\s]*href="([^"]+)"[\s]*title="Go to page ([0-9]+)">/g) {
				my $l = 'http://www.cvedetails.com'.$1;
				push(@vuln_page_links, $l);
			}
			$res = '';
			foreach my $l(@vuln_page_links) {
				$res .= request($l);
			}
		}
		elsif ($pagek eq 'Ven') {
			while ($res =~ /<a title="([^"]+)" href="([^"]+)">[0-9]+<\/a>/g) {
				my $l = 'http://www.cvedetails.com'.$2;
				push(@vuln_page_links, $l);
			}
			$res = '';
			foreach my $l(@vuln_page_links) {
				$res .= request($l);
			}
		}
		
		
	}#print "\n\n###\n\n$total_results\n\n##\n";print "\n\n\n\nRES dentro: ".length($res)."\n\n\n\n\n\n\n\n\n";
	
	if ($pagek ne 'Ven') {
		return('TOT_RES'.$total_results.'TOT_RES'.$res);
	}
	else {
		return($res);
		
	}
}

# function try_match :

# Return(0) -> No Match
# Return(1) -> Full Match
# Return(2) -> Partial match

sub try_match() {
	my($a,$b) = @_;

	my $matched = 0;
	my $version_key;
	my $version_tex;
	my @found_info;
	
	$a =~ /^([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)%%%%%([^%]+)/;
	my($Fversion,$Flanguage,$Fupdate,$Fedition,$vuln_numb,$urlpt1,$urlpt2,$urlpt3,$urlpt4) = ($1,$2,$3,$4,$5,$6,$7,$8,$9);
	push(@found_info,$Fversion,$Flanguage,$Fupdate,$Fedition,$vuln_numb);

#print "A: $a\nB: $b\n";

	if ($b =~ /^([0-9\-\.]+)$/) {#print "confronto: $b con $Fversion\n";
		# The user supplied version is only in the synatx: (Ex)->  2.3.4.5.00
		if (($Fversion =~ /^$b$/i)||($b =~ /^$Fversion$/i)||($Fversion eq $b)) {#print "passatooo\n";
			# Ok, the Numeric version match. let'see see for further details: (Ex)-> Beta|SP1 ..
			if (($Flanguage != 'NULL')||($Fupdate != 'NULL')||($Fedition != 'NULL')) {#print "PmAtchato\n";
				#yprint(	'[] Matched. Additional info were reported with the version:\n');
				my $str;
				my $count = 0;
				foreach my $i(@found_info) {
					$count++;
					if ($i != 'NULL') {
						if ($count == 1) {
							$str .= "    Version: ".$i."\n";
						}
						elsif ($count == 2) {
							$str .= "    Language: ".$i."\n";
						}
						elsif ($count == 3) {
							$str .= "    Update: ".$i."\n";
						}			
						elsif ($count == 4) {
							$str .= "    Edition: ".$i."\n";
						}
						elsif ($count == 5) {
							$str .= "    Vulnerabilities: ".$i."\n";
						}
					}
				}
				#yprint('[+] Details:\n$str\n[+] Can you confirm that this is the right version ?\n[+] Choice (y/n): ');
				#chomp(my $choice = <STDIN>):
				#if ($choice == 'y') {
				$matched = 2;
				push(@partial_matches, $str)
				#}
			}
			else {#print "mAtchato\n";
				$matched = 1;
			}	
		}
		else {
			## ! Debug : NO MATCH : given version(numeric) - found version(numeric)
		}
	}
	else {
		my $ok = 0;
		if ($b =~ /^([0-9\.-]+) (.+)$/) {
			$version_key = $1;
			$version_tex = $2;
			$ok = 1;
		}
		elsif ($b =~ /^([0-9.]+)([-;]+)(.+)/) {
			$version_key = $1;
			$version_tex = $3;
			$ok = 1;
		}
		else {
			#print "can't grep the version: $b\n";
		}
		if (($ok ==1)&&(($Fversion =~ /$version_key/i)||($$version_key =~ /$Fversion/i)||($Fversion eq $version_key))) {
			# Ok, the Numeric version match. let'see see for further details: (Ex)-> Beta|SP1 ..
			# Gonna compare now with $version_tex
			my $ok = 0;
			my $ok2 = 0;
			if (($Flanguage != 'NULL')||($Fupdate != 'NULL')||($Fedition != 'NULL')) {
				if (($Flanguage != 'NULL')&&(($Flanguage =~ /$version_tex/i)||($version_tex =~ /$Flanguage/i))) {
					$ok++;
					$ok2++;
				}
				if (($Fupdate != 'NULL')&&(($Fupdate =~ /$version_tex/i)||($version_tex =~ /$Fupdate/i))) {
					$ok++;
					$ok2++;
				}
				if (($Fedition != 'NULL')&&(($Fedition =~ /$version_tex/i)||($version_tex =~ /$Fedition/i))) {
					$ok++;
					$ok2++;
				}
				if ($ok == $ok2) {
					# All match, perfect ?!
					$matched = 1;
					# $ok here would already be '2' because already matched the $version_key
					#$matched = 2;
				}
				else {
					# $ok here would already be '2' because already matched the $version_key
					$matched = 2;
				}
			}
			else {
				# User input was : 2.0.0 something
				# Just found the version .. cvedetails does not know anything about this something. Partial
				$matched = 2;
			}	
		}
	}

	
	
	my $str_back = 	"    Version: ".$Fversion."\n    Language: ".$Flanguage.
					"\n    Update: ".$Fupdate."\n    Edition: ".$Fedition."\n    Vulnerabilities: $vuln_numb\n";
	my $url_str = 'http://www.cvedetails.com/vulnerability-list/'.$urlpt1.'/'.$urlpt2.'/'.$urlpt3.'/'.$urlpt4;
		
	if ($matched == 0) {
		push(@no_matches,$str_back);
		push(@no_urls,$url_str);
	}
	elsif ($matched == 2) {
		push(@partial_matches,$str_back);
		push(@partial_urls,$url_str);
	}
	
	my @back;
	push(@back,$matched,@no_matches,@no_urls,@partial_matches,@partial_urls);
	return($matched);
}


sub vuln_listing() {
	my($link,$version_given,$product_name_) = @_;
	my $at_least_one_vuln = 0;
	my $stop 	= 0;
	my $res 	= request($link);
	$res 		= &get_no_ofitems($res,'Vu',$link);
	$res =~ /^TOT_RES([0-9]+)TOT_RES/;
	my $tot_vuln_found = $1;
	$res =~ s/^TOT_RES[0-9]+TOT_RES//;
	
	if ($tot_vuln_found < 1) {
		return(0); # There were no vulns 0.0
	}
	
	yprint(	"[+] Version $version_given is affected by : $tot_vuln_found vulnerabilities !\n".
			"    Type now your choice:\n    1 - List them all\n    2 - Filter listing\n\n");
	
	
	
	my($vuln_type,$vuln_auth,$Afilter,$Bfilter,$Cfilter,$Dfilter,$FILTER,$from,$to,$equal,$FILTER_STATUS) = ('','','','','','',0,'','','',0);

	my($ch,$good_choice) = (0,0);
	while (($good_choice != 1)||($ch eq 'ex')) {
		yprint("[+] Choice: ");
		chomp($ch = <STDIN>);
		if ($ch =~ /^[1-2e]$/i) {
			$good_choice = 1;
		}
		else {
			yprint("[-] Bad input ! (If you want to exit, hit 'e')\n");
		}
	}
	
	if ($ch =~ /^e$/i) {
		# List all CVE
		return('R');
	}
	elsif ($ch == 2) {
		# Listing filtered by user selected options
			
		my $Aspace 				= 	'                                    ';
		my $vuln_type_inputs 	= 	"overflow, d0s, bypass, code execution,\n".$Aspace.
									"memory corruption, info disclosure,\n".$Aspace.
									"priv escalation, http response splitting,\n".$Aspace.
									"directory traversal, sql inj, xss, csrf,\n".$Aspace.
									"file inclusion\n";
		my $vuln_type_gx		= 	'overflow|d0s|bypass|code execution|memory corruption|info disclosure|'.
									'priv escalation|http response splitting|directory traversal|sql inj|x'.
									'ss|csrf|file inclusion|n';
		my $Bspace 				= 	'                                   ';
		my $vuln_risk_inputs 	= 	">= 5      (from 5.0 to 10.0)\n".$Bspace.
									"4         (from 4.1 to 4.9)\n".$Bspace.
									"3.0       (only 3.0)\n".$Bspace.
									"6<=v<10   (from 6.0 to 9.9)\n";
		my $vuln_risk_gx		= 	"^([0-9v=>< \.]+)\$";
		my $Cspace 				= 	'                                             ';
		my $vuln_auth_inputs 	= 	"none -> Pre Auth\n".$Cspace.
									"single -> Post Auth (single auth)\n".$Cspace.
									"multiple -> Post Auth (multiple auth)\n";
		my $vuln_auth_gx 		= 	'none|single|multiple|n';
		my $Dspace 				= 	'                                     ';
		my $vuln_access_inputs 	= 	"remote -> Remote exploitation\n".$Dspace.
									"local -> Local Exploitation\n";
		my $vuln_access_gx 		= 	'remote|local|n';
			
				
		yprint(	"[+] Filters in action\n    . if you don't want to enable a filter, hit 'n' when promped\n".
				"    . if you want all values except one (in vuln type filter) type : NO<value> (Ex: NOxss)\n\n");
			
		# Vulnerability Type
		my($ch1,$good_choice2) = (undef,0);
		while ($good_choice2 != 1) {
			yprint("    [!] Vulnerability Type values:  $vuln_type_inputs\n    [+] Type: ");
			chomp($ch1 = <STDIN>);
			if ($ch1 =~ /^(NO)*($vuln_type_gx)$/i) {
				$good_choice2 = 1;
			}
			else {
				yprint("[-] Bad input ! (If you want to exit, hit 'ex')\n");
			}	
		}
		if ($ch1 =~ /^ex/i) {
			&safe_close();
		}
		elsif ($ch1 =~ /^(NO)*($vuln_type_gx)$/i) {	#print "cvcvcvcvcvcvcv\n\n\n\n";	
			my($pre,$input) = ($1,$2);
					
			if ($input =~ /d0s/) {
				$vuln_type = 'dos';
			}
			elsif ($input =~ /code execution/) {
				$vuln_type = 'exec code';
			}
			elsif ($input =~ /memory corruption/) {
				$vuln_type = 'mem. corr.';
			}
			elsif ($input =~ /info disclosure/) {
				$vuln_type = 'info';
			}
			elsif ($input =~ /priv escalation/) {
				$vuln_type = 'priv';
			}
			elsif ($input =~ /directory traversal/) {
				$vuln_type = 'dir. trav.';
			}
			elsif ($input =~ /http response splitting/) {
				$vuln_type = 'http r.spl.';
			}
			elsif ($input =~ /sql inj/) {
				$vuln_type = 'sql';
			}
			elsif ($input =~ /^n$/) {
				$vuln_type = '';
			}
			else {
				$vuln_type = $input;
			}
			#print "input: $input - vuln: $vuln_type\n\n";
			if (length($vuln_type) > 0) {
				if ($pre eq 'NO') {
					$Afilter = 'NO'.$vuln_type;
				}
				else {
					$Afilter = $vuln_type;#print "djhfgdfjgdfjdfgdfhjfdjhfdgfhjdgdfhjgfdhjdfghjdfghfdjgfdhjgfdhjdfg: $Afilter\n\n";
				}
				$FILTER++;
			}
		}

 
		# Vulnerability Risk
		my($ch1,$good_choice2,$rfw) = (undef,0,0);
		while ($good_choice2 != 1) {
			yprint("    [!] Vulnerability Risk syntax: $vuln_risk_inputs\n    [+] Risk: ");
			chomp($ch1 = <STDIN>);
			if (($ch1 =~ /^([0-9]+)$/)||($ch1 =~ /^([0-9\.]+)$/)||($ch1 =~ /^(<=|<|>=|>)\s*([0-9]+)$/i)||($ch1 =~ /^([0-9]+)\s*(<=|<)\s*v\s*(<=|<)\s*([0-9]+)$/i)) {
				$good_choice2 = 1;
				$rfw = 1;
				$FILTER++;
			}
			elsif (($ch1 =~ /^ex/i)||($ch1 eq 'n')) {
				$good_choice2 = 1;
			}
			else {
				yprint("[-] Bad input ! (If you want to exit, hit 'ex')\n");
			}	
		}
		
		if ($ch1 =~ /^ex/i) {
			&safe_close();
		}
		elsif ($ch1 =~ /^([0-9]+)$/) {
			# ex: 4 (from 4.1 to 4.9)
			my $n  = $1;
			$from  = $n.'.1';
			$to    = $n.'.9';
			$equal = '';
		}
		elsif ($ch1 =~ /^([0-9\.]+)$/) {
			# ex: 3.0 (only 3.0)
			my $n = $1;
			$equal = $n;
			$from  = '';
			$to    = '';
		}
		else {####### add 4.3 (example)
			# user supplied > < = chars
			$equal = '';
			if ($ch1 =~ /^(<=|<|>=|>)\s*([0-9]+)$/) {
				# ex: [< 3] [<= 4] [> 6] [>= 8]
				my($sign,$numb) = ($1,$2);
				if ($sign =~ /=/) {
					# >= <=
					if ($sign =~ /^>/) {
						# >=
						$from = $numb.'.0';
						$to   = '10.0';	
					}
					elsif ($sign =~ /^</) {
						# <=
						$from  = '0.0';
						$to    = $numb.'.0';
					}	
				}
				else {
					# < >
					if ($sign =~ /^>/) {
						# >=
						$from = $numb.'.1';
						$to   = '10.0';	
					}
					elsif ($sign =~ /^</) {
						# <=
						$from  = '0.0';
						$to    = --$numb.'.9';
					}
				}
			}
			elsif ($ch1 =~ /^([0-9]+)\s*(<=|<)\s*v\s*(<=|<)\s*([0-9]+)$/) {
				my($numA,$signA,$signB,$numB) = ($1,$2,$3,$4);
								
				if ($signA =~ /=/) {
					$from = $numA.'.0';
				}
				else {
					$from = $numA.'.1';
				}
				if ($signB =~ /=/) {
					$to    = $numB.'.0';
				}
				else {
					$to = --$numB.'.9';
				}
			}
		}

		if ($rfw == 1) {
			$Bfilter = '!Equal!'.$equal.'!From!'.$from.'!To!'.$to;
		}
			
			
		# Authentication
		my($ch1,$good_choice2) = (undef,0);
		while ($good_choice2 != 1) {
			yprint("    [!] Vulnerability Authentication values: $vuln_auth_inputs\n    [+] Auth: ");
			chomp($ch1 = <STDIN>);
			if (($ch1 =~ /^($vuln_auth_gx)$/i)||($ch1 =~ /^ex/i)) {
				$good_choice2 = 1;
			}
			else {
				yprint("[-] Bad input ! (If you want to exit, hit 'ex')\n");
			}	
		}	
		if ($ch1 =~ /^($vuln_auth_gx)$/i) {	
			my $input = $1;
			if ($input =~ /none/) {
				$vuln_auth = 'not required';
			}
			elsif ($input eq 'n') {
				$vuln_auth = '';
			}
			else {
				$vuln_auth = $input;
			}
			if (length($vuln_auth) > 0) {
				$Cfilter = $vuln_auth;
				$FILTER++;
			}
		}
		elsif ($ch1 =~ /^ex/i) {
			&safe_close();
		}
		
		
		# Access
		my($ch1,$good_choice2) = (undef,0);
		while ($good_choice2 != 1) {
			yprint("    [!] Vulnerability Access values: $vuln_access_inputs\n    [+] Access: ");
			chomp($ch1 = <STDIN>);
			if (($ch1 =~ /^($vuln_access_gx)$/i)||($ch1 =~ /^ex/i)) {
				$good_choice2 = 1;
			}	
			else {
				yprint("[-] Bad input ! (If you want to exit, hit 'ex')\n");
			}	
		}
		if ($ch1 =~ /^($vuln_access_gx)$/i) {		
			my $input = $1;
					
			if ($input eq 'n') {
				$input = '';	
			}
			if (length($input) > 0) {
				$Dfilter = $input;
				$FILTER++;
			}
		}
		elsif ($ch1 =~ /^ex/i) {
			&safe_close();
		}
	}

	# $1 -> ID
	# $2 -> CVE
	# $3 -> No of exploits
	# $4 -> Vulnerability Type (must be cleaned) (xss,d0s,etc ..)
	# $5 -> Publish day
	# $7 -> Risk (Score)
	# $8 -> Gained Access Level (None, User, Admin)
	# $9 -> Access (Remote, Local)
	# $11 -> Authentication (Not required, Single system)

	my $regexp = 	"<\/a>[\\s]*([0-9]+)[\\s]*<\/td>[\\s]*<td nowrap><a[^>]+>([^<]+)<\/a><\/td>[\\s]*<td><*a*[^<]*<*\/*a*>*<\/td>[\\s]*<td class=\"n".
					"um\">[\\s]*<b style=\"color:red\">([^<]*)<\/b>[\\s]*<\/td>[\\s]*<td>([^<]*)<\/td>[\\s".
					"]*<td>([^<]+)<\/td>[\\s]*<td>([^<]+)<\/td>[\\s]*<td><div[^>]+>([^<]+)<\/div><\/td>[\\s]*<td ".
					"align=\"center\">([^<]+)<\/td>[\\s]*<td align=\"center\">([^<]+)<\/td>[\\s]*<td al".
					"ign=\"center\">([^<]+)<\/td>[\\s]*<td align=\"center\">([^<]+)<\/td>[\\s]*<td alig".
					"n=\"center\">([^<]+)<\/td>[\\s]*<td align=\"center\">([^<]+)<\/td>[\\s]*<td align".
					"=\"center\">([^<]+)<\/td>";

	my $tot_vuln_counter = 0;
	my $stop = 0;
	my $FILTER_STATUSZ = 0;
	while ($res =~ /$regexp/gi) {

		my($id,$CVE,$tot_spl,$vuln_typef,$publish_day,$risk,$gain_priv,$acc,$auth) = ($1,$2,$3,$4,$5,$7,$8,$9,$11);
		
		### ALL vars must be CLEANED from shit \s etc etc, unless they will fuck the match up.

		my(@tmp_array,@cleaned_sgreps);
		push(@tmp_array,$id,$CVE,$tot_spl,$vuln_typef,$publish_day,$risk,$gain_priv,$acc,$auth);
		foreach my $e(@tmp_array) {
			my $copy = $e;
			if ($copy =~ /[a-zA-Z0-9\.\-]+/) {
				$copy =~ s/^([^a-zA-Z0-9]+)([A-Za-z0-9\.\-\s]+)/$2/g;
				$copy =~ s/([\s]{2,})//;
			}
			else {
				$copy = 'NULL';
			}
			push(@cleaned_sgreps,$copy);
		}
		my $str = join '£', @cleaned_sgreps;

		$str =~ /^([^£]+)£([^£]+)£([^£]+)£([^£]+)£([^£]+)£([^£]+)£([^£]+)£([^£]+)£([^£]+)$/;#print "\n\nSTR: $str\n\n";
		my($id,$CVE,$tot_spl,$vuln_typef,$publish_day,$risk,$gain_priv,$acc,$auth) = ($1,$2,$3,$4,$5,$6,$7,$8,$9);
		if ($vuln_typef eq 'NULL') {
			$vuln_typef = 'Unk';
		}

		$tot_vuln_counter++;
		my $vuln_is_ok = 0;
		
		if ((length($Afilter) < 1)&&(length($Bfilter) < 1)&&(length($Cfilter) < 1)&&(length($Dfilter) < 1)) {#print "NO FILTRI\n";
			# No filters ... List ALL
			$vuln_is_ok = 1;
		}
		else {
			# Filters ....
			$FILTER_STATUSZ = 1;
			my $FILTER_ = 0;
			
			if (length($Afilter) > 0) {#print "FIltro TYPE: $Afilter VS $vuln_typef\n";
				# Type

				if ($Afilter =~ /^NO(.+)$/) {
					my $afilter = $1;
					if ($vuln_typef eq 'Unk') {#print "escludi ... ma unk, quindi ce ne fottiamo , non black ..\n";
						$FILTER_++;
						$vuln_typef = '!! Unknown - Check if type is != '.$afilter;
					}
					else {
						# If we are here, it means that user want all type of vuln EXCEPT one.
						# Could be that one CVE has more kind of vulns ... If there are many,
						# and on of them is kind the user does not want, we don't care cos the
						# cve has other vuln kind that the user wants ...
						# BUT, if the only kind of vuln of the CVE is exaclty the one the user
						# does not want ... CVE 'blacklisted' :D
						my(@tmp_,@found);
						while ($vuln_typef =~ /([^ ]+)/g) {
							my $i = $1;
							if ($i =~ /dos|code|corr|info|priv|trav|spl|sql|xss|csrf|incl|overflow|bypass/i) {
								push(@tmp_,$i);
							}
						}

						my($c,$fo) = 0;
						foreach my $t(@tmp_) {
							if (length($t) > 0) {
								if ($t =~ /$afilter/i) {
									$fo = 1;
								}
								push(@found,$t);
							}
						}
						if (($fo == 1)&&(scalar(@found) > 1)) {#print "elemento escludi ($Afilter) trovato in $vuln_typef..\nma ci sono anche altre merde .. quindi non black\n";
							$FILTER_++;
							# In the vuln type there is the 'blacklisted' one, but also other .. so skip
						}
						elsif (($fo == 1)&&(scalar(@found) == 1)) {
							#print "elemtno escludi ($Afilter) trovato in $vuln_typef .. ma non ce ne sono altri .. blacklisted\n";
						}
						else {
							#print "mm ...vulmtypef: $vuln_typef ... non c'Ã¨ il black: $Afilter .. non black\n";
							$FILTER_++;
						}
					}
				}
				else {
					if (($vuln_typef eq 'Unk')||($vuln_typef =~ /$Afilter/i)) {#print "A: filtro OK\n";
						# OK. This CVE has the same vuln type selected by the user.
						if ($vuln_typef eq 'Unk') {
							$vuln_typef = '!! Unknown - Check if type is '.$Afilter;
						}
						$FILTER_++;
					}
				}
			}
			if (length($Bfilter) > 0) {#print "FIltro RISK: $Bfilter VS $risk\n";
				# Risk
				
				$Bfilter =~ /^!Equal!([^!]*)!From!([^!]*)!To!(.*)$/;
				my($equal,$from,$to) = ($1,$2,$3);
				
				if (length($equal) > 0) {#print "Equal settato: $equal --- versus $risk\n";
					if ($equal =~ /$risk/) {
						$FILTER_++;#print "B1: filtro OK\n";
					}
				}
				else {#print "From e to: $from ---- $to ---- versus $risk\n";
					if (($risk >= $from)&&($risk <= $to)) {
						$FILTER_++;#print "B2: filtro OK\n";
					}
				}
			}
			if (length($Cfilter) > 0) {#print "FIltro AUTH: $Cfilter VS $auth\n";
				# Auth
				if ($Cfilter =~ /$auth/i) {#print "C: filtro OK\n";
					$FILTER_++;
				}
				
			}
			if (length($Dfilter) > 0) {#print "FIltro ACC: $Dfilter VS $acc\n";
				# Access
				if ($Dfilter =~ /$acc/i) {#print "D: filtro OK\n";
					$FILTER_++;
				}
				
			}
			if ($FILTER == $FILTER_) {#print "TUTTI filtri passati !!!!!\n\n\n";
				# This row is 100 % ok. Matched all user filters
				$vuln_is_ok = 1;
			}
		}
		
		
		######
		if ($vuln_is_ok == 1) {
			$at_least_one_vuln++;
			my $str = ':ID:'.$id.':CVE:'.$CVE.':NSPL:'.$tot_spl.':TYP:'.$vuln_typef.':RISK:'.$risk.':PRIV:'.$gain_priv.':ACC:'.$acc.':AUTH:'.$auth;
			#print "metto str in vulntogo: $str\n";
			push(@vuln_to_go,$str);
			
		}
		if ($tot_vuln_found == $tot_vuln_counter) {#print "\n\nFINEEE\n\n";
			$stop = 1;
		}
	}
	if ($at_least_one_vuln > 0) {
		go_CVE($product_name_,$version_given,$FILTER_STATUSZ);
		return(1); # At least one vuln is OK
	}
	else {
		# Vulns were found, but none were OK because of the user FILTER
		return(2);
	}
}

sub go_CVE() {
	my($product,$version,$filterSTat) = @_;
	my $total_vuln_to_log = scalar(@vuln_to_go);
	$found_vulns_yes_mm++;
	
	
	#if (($found_vulns_yes_mm == 1)&&(($option_ch == 2)||($option_ch == 4))) {
	#	yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="Vulnerabilities">'."\n",3);
		
	#}
	
	
	
	
	
	
	
	my $counter = 0;
	
	if ($filterSTat == 0) {
		$filterSTat = 'Off';
	}
	else {
		$filterSTat = 'On';
	}
	my $tot_exploit_av = 0;
	my $tot_metasploit_av = 0;
	
	# stringa di ricerca da applicare per incollare nel report la roba tra header e footer:
	# </div><div id="footer"><p>T 1300 031337 T +61 2 9375 2424 F +61 2 9375
	# prima del primo carattere di sta stringa ... sta per iniziare il footer
	
	
	
	# mancano : :TOT_METAS: :TOT_SPLOITS:

	my $html_search = 	'<div class="seach_main_element"><div class="main_element_title"><div class="main_element_title_l"><p>Vulnerabilities for &nbsp;&gt;&nbsp; '.
						$product.'/'.$version.' - Filter(s): '.$filterSTat.' - CVE matched: '.$total_vuln_to_log.'</p></div><div class="main_element_title_r">'.
						'<a onclick ="element(\''.$div_report_C.'\'); return false;" href="#"><img src="./graphic/icon_panel_minimize.png" /></a></div></div>'.
						'<div id="CVE_container_'.$div_report_C.'" style="display:block;"><div class="search_summary"><table class="summary_table"><tr'.$tr_str.'>'.
						'<td class="srowA">Product</td><td class="srowB">'.$product.'</td></tr><tr'.$tr_str.'><td class="srowA">Version</td><td class="srowB">'.$version.'</td>'.
						'</tr><tr'.$tr_str.'><td class="srowA">Filters</td><td class="srowB">'.$filterSTat.'</td></tr><tr'.$tr_str.'><td class="srowA"># CVE</td><td class="srowB">'.
						$total_vuln_to_log.'</td></tr><tr'.$tr_str.'><td class="srowA"># Exploits</td><td class="srowBB">:TOT_SPLOITS:</td></tr><tr'.$tr_str.'>'.
						'<td class="srowA"># Metasploit</td><td class="srowBB">:TOT_METAS:</td></tr></table></div>';
	
	
	my $html_append = '';
	my $mm_string = '[AAA]['.$product.'/'.$version.']';
	foreach my $str(@vuln_to_go) {#print $str."\n";
		$counter++;
		$str =~ /^:ID:(.+):CVE:(.+):NSPL:(.+):TYP:(.+):RISK:(.+):PRIV:(.+):ACC:(.+):AUTH:(.+)$/;
		
		# data from cvedetails.com
		
		my($id,$CVE,$tot_spl,$typ,$risk,$priv,$acc,$auth) = ($1,$2,$3,$4,$5,$6,$7,$8);
		
		my $Ccvedetails_link = 'http://www.cvedetails.com/cve/'.$CVE.'/';
		my $Ccve_summary_regexp = '<div class="cvedetailssummary">(.+)<span class="datenote">.*Publish Date : '; ## clean $1 - summary regards the CVE (from cvedetails.com)
		
		# $1 -> external resource link
		# $2 -> link to print - if ^http://www.securityfocus.com/bid/48259$ ...
		# $3 -> additional info to print - must be cleaned
		my $Cext_resources_regexp = '<a href="([^"]+)" target="_blank" title="External url">([^<]+)<\/a>[\\s]*<br\/>([^<]*)(<\/td>)*';

		my $length_str = "[".$counter."/".$total_vuln_to_log."]";
		my $space = '';
		my $nspace;
		my $length = length($length_str);
			
		my $lc = 0;
		while ($lc < $length) {
			$space .= ' ';
			$lc++;
		}
		$nspace = $space;
		$space = '                        ';

		$spaceH = "                              ";

		# Get description from cvedetails.com
		my $Ccve_summary;#print "$Ccvedetails_link\n";
		my $Cres = &request($Ccvedetails_link);#print "ok ..\n";
		$Cres =~ s/\t/:TAB:/g;#print "$Sres\n";exit;
		$Cres =~ s/\f/:FFF:/g;
		$Cres =~ s/\n/:NNN:/g;
		$Cres =~ s/\r/:RRR:/g;
		if ($Cres =~ /$Ccve_summary_regexp/) {
			$Ccve_summary = $1;		# NEEDS TO BE CLEANED FROM HTML CODE AND SHIT	
		}
		else {
			## Strange, no vuln description from cvedetails. (99,999999 % will be a regexp dismatch)(won't happen ;-))
		}
		# Get external resources from cvedetails.com
		my($Cext_resource, $Cinfo_a, $Cinfo_b,@Cexternal_resources,$securityfocus);
		my($SFtitle,$SFdiscussion,@SFexploits_link,$SFexp,$SFsolution,$SFtitleS,$SFdiscussionS);
		if ($Cres =~ /<strong style="color:red;">Exploit!<\/strong>[^<]*<a href="([^"]+)" target="_blank" title="External url">/i) {
			push(@SFexploits_link,$1);#print "hjdhjdhjdhjdhdjhdjhdjhd\n: $1\n";
			$SFexp = 1;
		}
		
		
		while ($Cres =~ /$Cext_resources_regexp/g) {
			($Cext_resource, $Cinfo_a, $Cinfo_b) = ($1,$2,$3);
			
			if ($Cext_resource =~ /www\.securityfocus\.com\/bid\//) {
				$securityfocus = $Cext_resource;
			}
			
			my $str = 'AA:'.$Cext_resource.'BB:'.$Cinfo_b;
			push(@Cexternal_resources,$str);
		}
		#print "kjhkhkj\n";
		# I found a securityfocus resource, let's use it to compare stuff, as well as grab sploits if exist

		my @Sexploits_link;
		my $SF = 0;
		
		
		#if $SFexp ==1 testa array di sploit, senno no printa $SFexp che dice che non ce ne sono
		# if $SFsolution != 0 allora contiene la soluzione -> $SFtitleS,$SFdiscussionS

		if (length($securityfocus) > 0) {
		
		# <li><a href="http:// ....
		
		# <li><a href="http://www.php.net/ChangeLog-5.php">PHP Changelog</a> (PHP)<br/></li>
		
			$SF = 1;
			my $discuss_link = $securityfocus.'/discuss';
			my $discuss_gx =
			
			my $exploit_link = $securityfocus.'/exploit';
			my $exploit_gx =
			
			my $solution_link = $securityfocus.'/solution';
			my $solution_gx = 
			
			#my @securityfocus_staff = ('/discuss','/exploit','/solution','/references');
			my @securityfocus_staff = ('/discuss','/exploit','/solution'); # /references requested only if info about solutions are in the references
			my $c = 0;
			foreach my $i(@securityfocus_staff) {
				$c++;
				my $link = $securityfocus.$i;#print "\n$link\n"
				my $Sres = &request($link);
				$Sres =~ s/\t/:TAB:/g;
				$Sres =~ s/\f/:FFF:/g;
				$Sres =~ s/\n/:NNN:/g;
				$Sres =~ s/\r/:RRR:/g;
				
				if ($c == 1) {
					if ($Sres =~ /<div id="vulnerability">[^<]*<span class="title">(.+)<\/span><br\/><br\/>(.+)<\/div>/) {
						($SFtitle,$SFdiscussion) = ($1,$2);
					}
					else {
						# no securityfocus discussion 
					}
					
				}
				elsif ($c == 2) {
					if ($Sres =~ /Currently we are not aware of any wor/) {
						if ($Sres =~ /commercial|publicy/) {
							$SFexp = "Private\n";
						}
						else {
							$SFexp = "0 exploits available\n";
						}
					}
					
					elsif ($Sres =~ /\/data\/vulnerabilities\//) {
						$SFexp = 1;
						while ($Sres =~ /<li><a href="\/data\/vulnerabilities\/exploits\/([^"]+)">/g) {
							my $abs_link = 'http://www.securityfocus.com/data/vulnerabilities/exploits/'.$1;
							push(@SFexploits_link,$abs_link);
						}
					}
					else {
						#A working commercial exploit is available through VUPEN Security - Exploit and PoCs Service. This exploit is not otherwise publicly available or known to be circulating in the wild.
						if ($Sres =~ /commercial|publicy/) {
							$SFexp = "Private\n";
						}
						elsif ($Sres =~ /wing proof-of-concept code is av/) {
							$SFexp = 1;
							push(@SFexploits_link,$link);
						}
						else {
							$SFexp = "0 exploits available\n";
						}
						#Core Security Technologies has developed a working commercial exploit for its CORE IMPACT product.
						# This exploit is not otherwise publicly available or known to be circulating in the wild.
					}
				}
				elsif ($c == 3) {
					$SFsolution = 0;
					if ($Sres !~ /tly we are not aware of any ven/) {
						if ($Sres =~ /<div id="vulnerability">[^<]*<span class="title">(.+)<\/span><br\/><br\/>(.+)<\/div>/) {
							($SFtitleS,$SFdiscussionS) = ($1,$2);
							$SFsolution = 1;
							
							if ($SFdiscussionS =~ /se see the references for m/) {
								my $link = $securityfocus.'/references';
								my $re = &request($link);
								$re =~ s/\t/:TAB:/g;
								$re =~ s/\f/:FFF:/g;
								$re =~ s/\n/:NNN:/g;
								$re =~ s/\r/:RRR:/g;
								#<li><a href="http://www.php.net/ChangeLog-5.php">PHP Changelog</a> (PHP)<br/></li>
								#<li><a href="http://([^"]+)">([^<]+)<\/a>
								my $st;
								while ($re =~ /<li><a href="http:\/\/([^"]+)">([^<]+)<\/a>/g) {
									my $ref = $spaceH.'http://'.$1.'    -    '.$2;
									$st .= $ref."\n";
								}
								$st = "\n".$st;
								$SFdiscussionS = $SFdiscussionS.$st;
							}
						}#else {print "non trovato soluzioneehehehehe\n";}
					}#else {print "non trovato solzuione\n";}
				}
			}
		}#else {print "nada securityfocus ..\n";}

		# Metasploit search
		my $Mmetasploit_search_url = 'http://www.metasploit.com/modules/framework/search?utf8=%E2%9C%93&osvdb=&bid=&text=&cve='.$CVE.'&msb=';
		my $Mmetasploit_exploit_url_regexp = '<a href="([^"]+)">Source Code<\/a>';
		my $Mmetasploit_code_link = "Not available";
		my @Mmodules_links;
		my $Mres = &request($Mmetasploit_search_url);
		my $M = 0;
		if ($Mres !~ /No results matched your query/) {
			# There is a metasploit exploit/module available for this CVE
			
			# if multiple results from search (more than 1 module/exploit for a CVE)
			
			if ($Mres =~ /<h4>Search Results<\/h4>/) {
				$Mmetasploit_code_link = '';
				while ($Mres =~ /<a href="([^"]+)">MODULE USAGE<\/a><\/li>/g) {
					my $l = "http://metasploit.com".$1;
					push(@Mmodules_links,$l);
					my $Mre2 = &request($l);
					if ($Mre2 =~ /$Mmetasploit_exploit_url_regexp/) {
						$Mmetasploit_code_link .= $1."<br>";
						$tot_metasploit_av++;
					}
					
				}
				$Mmetasploit_code_link =~ s/<br>$//;
			}
			elsif ($Mres =~ /$Mmetasploit_exploit_url_regexp/) {
				$Mmetasploit_code_link = $1;
				$tot_metasploit_av++;
			}

			else {
				# I think you'll never be in this situation .. however ...
			}
		}
		
		my $ptitle;
		if ($SF == 1) {
			$ptitle = "  -   ".$SFtitle;
		}
		
		my $pdesc;
		if ($SF == 1) {
			$pdesc = $SFdiscussion;
		}
		else {
			$pdesc = $Ccve_summary;
		}

		my $resource_string;
		
		if (scalar(@Cexternal_resources) > 0) {
			my $c = 0;
			foreach my $r(@Cexternal_resources) {
				$c++;
				my $sp = $space;
				my $sp2;
				if ($c == 1) {
					
					$sp2 = " ";
					
				}
				else {
					
					$sp2 = $spaceH;
				}
				$sp = $sp2."    ";
				$r =~ /^AA:(.+)BB:(.+)$/;#print "R: $r\n";
				my($a,$b) = ($1,'     '.$2);
				if ($b =~ /[a-zA-Z]+/) {
					$resource_string .= $sp2.$a."\n$sp$b\n\n";
				}
				else {
					$resource_string .= $sp2.$a."\n";
				}#print "aaa: $resource_string";				
			}	
		}
		else {
			$resource_string = "0\n";
		}
			
		if ($SFexp == 1) {
			$SFexp = "";
			my $c = 0;
			
			if (scalar(@SFexploits_link) > 1) {
				foreach my $e(@SFexploits_link) {
					$tot_exploit_av++;
					my $sp = $space;
					$c++;
					if ($c == 1) {
						$sp = "";
					}
					else {
						$sp = $space;
					}
					$SFexp .= $sp.$e."\n";
				}
			}
			else {
				$SFexp = $SFexploits_link[0]."\n";
				$tot_exploit_av++;
			}		
		}
		if (length($SFexp) < 1) {
			$SFexp = "0 Exploits available\n";
		}

		my $solution = "Non available or unknown";
		my $solutionL = "Non available or unknown";
		if ($SFsolution != 0) {
			if (length($SFdiscussionS) > 1000) {
				$solution = "Solution's length is > 1k chars, consult the .log report to see it.";
				$solutionL = "\n".$space.$SFdiscussionS;
			}
			else {
				$solution = "\n".$space.$SFdiscussionS;
				$solutionL = $solution;
			}
		}
		
		my @to_clean;
		push(@to_clean, $CVE, $ptitle, $typ, $risk, $priv, $acc, $auth, $pdesc, $resource_string, $solution, $SFexp, $Mmetasploit_code_link, $solutionL);
		#print "sdjhdjkhsdjksdhjksdhsdjkhdsjksdhsjdkhdsjkdshds $counter - $total_vuln_to_log\n";
		
		if (($option_ch == 2)||($option_ch == 4)) {
		
			$mm_string .= &clean_vars_for_normal_out($counter, $total_vuln_to_log,$nspace,$space,@to_clean);
		}
		else {
			&clean_vars_for_normal_out($counter, $total_vuln_to_log,$nspace,$space,@to_clean);
		}
		
		if ($file_st == 1) {
			$html_append .= &write_html_logfile(@to_clean);
			$html_append .= "<!--END_".$tot_search_completed."_DNE!-->";
		}
	}
	if (($option_ch == 2)||($option_ch == 4)) {#print "Pusho : $mm_string ...\n";
		$mm_string .= "[/AAA]";
		push(@mindmap_vulnerabilities_perhost,$mm_string);
	}
	
	
	if ($file_st == 1) {
		&write_to_html($html_append,$html_search,$tot_exploit_av,$tot_metasploit_av);
	}
	$tot_search_completed++;
}



sub clean_vars_for_normal_out() {
	my($counter,$total_vuln_to_log,$nspace,$space,@to_clean) = @_;#print "kdhj  jcsbsjkbjk cj cj $counter = $total_vuln_to_log\n";
	my @cleaned;
	
	#foreach my$i(@to_clean) {
	#	print $i."\n";
	#}
	
	
	@cleaned = map { html_to_plain_text($_,$space) } @to_clean;
	my @vars_to_print = ($counter, $total_vuln_to_log, $cleaned[0], $cleaned[1], $cleaned[2], $cleaned[3],$cleaned[4],
						$cleaned[5], $cleaned[6], $cleaned[7], $cleaned[8], $cleaned[9], $cleaned[10], $cleaned[11]);


	if ($file_st == 1) {
		&write_txt_logfile(@vars_to_print,$nspace,$space);
	}
	my $print_str = "\n\n[".$vars_to_print[0]."/".$vars_to_print[1]."] CVE                  : ".$vars_to_print[2]." ".$vars_to_print[3].
					"\n$nspace Type                 : ".$vars_to_print[4]."\n$nspace "."Risk                 : ".$vars_to_print[5].
					"/10\n$nspace Gained Access Level  : ".$vars_to_print[6]."\n$nspace Access               : ".$vars_to_print[7].
					"\n$nspace"." Authentication       : ".$vars_to_print[8]."\n$nspace Description          :\n".$space.
					$vars_to_print[9]."\n\n$nspace Resources            : ".$vars_to_print[10]."\n$nspace Solutions            : ".
					$vars_to_print[11]."\n$nspace Exploit(s)           : ".$vars_to_print[12]."\n".$nspace." Metasploit           : ".
					$vars_to_print[13]."\n\n";
					
	&yprint($print_str);
	
	
	if (($option_ch == 2)||($option_ch == 4)) {#print "\n\n\n\n\n\n\n\n\n\nAAAAAAAA\n";
		my($type,$expl,$met) = '';
		if ($vars_to_print[4] =~ /Unknown - Check if type is/) {
			$type = 'Unknown Type';
		}
		else {
			$type = $vars_to_print[4];
		}
		$expl = $vars_to_print[12];
		$met = $vars_to_print[13];
		#if (($vars_to_print[12] =~ /\n/)||($vars_to_print[13] =~ /\n/)) {
		#	$expl =~ s/\n/ /g;
		#	$met =~ s/\n/ /g;
		#}
	
		if ($expl =~ /\n/) {
			$expl =~ s/\n/ /g;
			if ($expl =~ /\s$/) {
				$expl =~ s/\s$//;
			}
		}
		if ($met =~ /\n/) {
			$met =~ s/\n/\s/g;
			if ($met =~ /\s$/) {
				$met =~ s/\s$//;
			}
		}
	
	
	
		my $string = "[CVE]".$vars_to_print[2]." ".$vars_to_print[3]."%%%%%".$type."%%%%%".$vars_to_print[7]."%%%%%".$vars_to_print[8]."%%%%%".$expl."%%%%%".$met."[/CVE]";
		#print $string."\n\n\n\n";
		#push(@mindmap_vulnerabilities_perhost,$string);
		return $string;
	}
	
	
	
	

}




sub write_txt_logfile() {
	my(@txt,$nspace,$space) = @_;
	
	my $line 	= 	'-----------------------------------------------------------------------'.
					'-----------------------------------------------------------------------';
								
	my $print_log_str = "\n\n$line\n[".$txt[0]."/".$txt[1]."] CVE                  : ".$txt[2]." ".$txt[3].
						"\n$nspace Type                 : ".$txt[4]."\n$nspace "."Risk                 : ".$txt[5].
						"/10\n$nspace Gained Access Level  : ".$txt[6]."\n$nspace Access               : ".$txt[7].
						"\n$nspace"." Authentication       : ".$txt[8]."\n$nspace Description          :\n".$space.$txt[9].
						"\n\n$nspace Resources            : ".$txt[10]."\n$nspace Solutions            : ".$txt[11].
						"\n$nspace Exploit(s)           : ".$txt[12].$nspace." Metasploit           : ".$txt[13]."\n$line\n\n";
	
	&yprint($print_log_str,1);
	
}

sub write_html_logfile() {
	my(@txt,$nspace,$space) = @_;
	
	my $str =	'<div class="cve_detail"><table class="cve_table"><tr'.$tr_str.'><td class="crowA">CVE</td><td class="crowBB">'.$txt[0].'   -   '.$txt[1].'</td>'.
				'</tr><tr'.$tr_str.'><td class="crowA">Type</td><td class="crowB">'.$txt[2].'</td></tr><tr'.$tr_str.'><td class="crowA">Risk</td><td class="crowB">'.$txt[3].'</td>'.
				'</tr><tr'.$tr_str.'><td class="crowA">Gained Access Level</td><td class="crowB">'.$txt[4].'</td></tr><tr'.$tr_str.'><td class="crowA">Access</td><td class="crowB">'.$txt[5].'</td>'.
				'</tr><tr'.$tr_str.'><td class="crowA">Authentication</td><td class="crowB">'.$txt[6].'</td></tr><tr'.$tr_str.'><td class="crowA">Description</td><td class="crowB">'.$txt[7].'</td>'.
				'</tr><tr'.$tr_str.'><td class="crowA">Resources</td><td class="crowB">'.$txt[8].'</td></tr><tr'.$tr_str.'><td class="crowA">Solutions</td><td class="crowB">'.$txt[9].'</td>'.
				'</tr><tr'.$tr_str.'><td class="crowA">Exploits</td><td class="crowBS">'.$txt[10].'</td></tr><tr'.$tr_str.'><td class="crowA">Metasploit</td><td class="crowBS">'.$txt[11].'</td>'.
				'</tr></table></div></div></div>';

	return($str);
}

sub write_to_html() {
	my($str,$str2,$tot_exploit_av,$tot_metasploit_av) = @_;
	
	
	$str2 =~ s/:TOT_SPLOITS:/$tot_exploit_av/;
	$str2 =~ s/:TOT_METAS:/$tot_metasploit_av/;
	
	my $string = $str2.$str;
	my $fstring = '';
	
	if ($tot_search_completed == 0) {
		open(HTMLReport, "<", $log_file.'.html');
		my $content;
	    while (my $a = <HTMLReport>) {
	        #$a =~ s/\n//g;
	        #push(@tot,$a);
			$content .= $a;
	    }#<!--END_".$tot_search_completed."_DNE!-->
	    $content =~ s/com<\/a><\/p><\/div><\/div><div id="content"><\/div><div id="footer"><p>T 130/com<\/a><\/p><\/div><\/div><div id="content">$string<\/div><div id="footer"><p>T 130/;
		yprint($content,3);
		
		
	}
	else {
		open(HTMLReport, "<", $log_file.'.html');
		my $content;
	    	while (my $a = <HTMLReport>) {
	        #$a =~ s/\n//g;
	        #push(@tot,$a);
			$content .= $a;
	    }#<!--END_".$tot_search_completed."_DNE!-->
	    $content =~ s/<!--END_([0-9]+)_DNE!--><\/div><div id="footer"><p>T 130/<!--END_$1_DNE!-->$string<\/div><div id="footer"><p>T 130/;
		yprint($content,3);
	
	
	}
	#$ssid = join '', @e_sid;
	#</p></div></div><div id="content">|||</div><div id="footer"><p>T 130
	
}





sub html_to_plain_text() {#print "entrato in html_to echdbdjh\n\n\n";
	my($mixed,$space) = @_;#print "space:$space:space\n";
	$mixed =~ s/\n/:NNN:/g;
	#print "--------\n\n$mixed\n\n--------\n";
	# replace substition i had to do (because of problems i had with HTML response/output matching) regexp fuckzed
	$mixed =~ s/:TAB://g;
	# what bout replacing tab with 4 spaces ?
	#$mixed =~ s/:TAB:/    /g;
	$mixed =~ s/:FFF://g;
	$mixed =~ s/:NNN:/\r\n$space/g;
	$mixed =~ s/:RRR://g;
	
	# html strip tags (the majors ..)
	$mixed =~ s/< *b *>//gi;
	$mixed =~ s/< *\/ *b *>//gi;
	$mixed =~ s/< *i *>//gi;
	$mixed =~ s/< *\/ *i *>//gi;
	$mixed =~ s/< *br *>/\r\n$space/gi;
	$mixed =~ s/< *\/ *br *>/\r\n$space/gi;
	$mixed =~ s/< *br *\/ *>/\r\n$space/gi;
	
	# html encoded -> html decoded
	$mixed =~ s/&ndash;/-/g;
	$mixed =~ s/&mdash;/-/g;
	$mixed =~ s/&quot;/"/g;
	$mixed =~ s/&ldquo;/“/g;
	$mixed =~ s/&rdquo;/”/g;
	$mixed =~ s/&#39;/'/g;
	$mixed =~ s/&lsquo;/‘/g;
	$mixed =~ s/&rsquo;/’/g;
	$mixed =~ s/&laquo;/« »/g;
	$mixed =~ s/&nbsp;/ /g;
	$mixed =~ s/&amp;/&/g;
	$mixed =~ s/&copy;/©/g;
	$mixed =~ s/&gt;/>/g;
	$mixed =~ s/&lt;/</g;
	$mixed =~ s/&euro;/€/g;
	
	if ($mixed =~ /\r\n\s*\r\n/) {#print "\n\ndjhdjh  uuuuuud\n\n";
		#if ($mixed =~ s/\r*\n\s*\r*\n/\r\n/g) {
		#	#print "ok\n";
		#}else {print "no\n";}
	}
	#print "\n\n-----\n$mixed\n\n\n";
	my $cleaned = $mixed;
	return($cleaned);	
}



sub analyze_xml() {
	my($input_file_content,$ops) = @_;#print "kjfdjfkjfdkfjdkfjkfd $ops\n";
	my $xml_string = '';



	#print $input_file_content."\n"

	while ($input_file_content =~ /<host ([^\n]+)<\/host>/g) {
		
		my $content = $1;
		my $sfou = 0;
		my @vuln_to_go_prods = ();
		splice(@soft_vers_spid_se,0);
		my($ip,$host,$port,$software,$version,$extras,$port_content,$status,$count,@extras);
		if ($content =~ /<address addr="([^"]+)"/) {
			$ip = $1;
		}
		if ($content =~ /<hostname name="([^"]+)"/) {
			$host = $1;
		}
		my $port_random = create_random_id();
		my $port_stram = '';
		if ($ops =~ /1|2|4/) {
			if ((length($host) > 1)&&(length($ip) > 0)) {
				$port_stram = '<node FOLDED="false" ID="'.create_random_id().'" POSITION="right" TEXT="'.$ip.'&#xA;'.$host.'"><node FOLDED="AAA" ID="'.$port_random.'" TEXT="Ports">'."\n";
			}
			else {
				if (length($ip) > 0) {
					$port_stram = '<node FOLDED="false" ID="'.create_random_id().'" POSITION="right" TEXT="'.$ip.'"><node FOLDED="AAA" ID="'.$port_random.'" TEXT="Ports">'."\n";
				}
			}
		}
		      
		if ($content =~ /<ports>(.+)<\/ports>/g) {      
			$port_content = $1;                       
			
			if ($port_content =~ /<extraports state="([^"]+)" count="([0-9]*)"/) {
				($status,$count) = ($1,$2);###
			}
			
			if ($port_content =~ /<port /) {
				$port_content =~ s/<port /\n\n<port /g;
			}
			if ($port_content =~ /<\/port>/) {
				$port_content =~ s/<\/port>/<\/port>\n\n/g;
			}
			
			my $ports_counter = 0;
			
			while ($port_content =~ /<port ([^\n]+)<\/port>/g) {
				$ports_counter++;
			}
			if ($ports_counter > 20) {
				$port_stram =~ s/FOLDED="AAA"/FOLDED="true"/;
			}
			else {
				$port_stram =~ s/FOLDED="AAA"/FOLDED="false"/;
			}
			#print "aa\n$port_stram\n\n";
			yprint($port_stram,3);
			
			
			while ($port_content =~ /<port ([^\n]+)<\/port>/g) {#print "o\n";
				my $sport_cont = $1;#print "$sport_cont\n\n\n";
				splice(@extras,0);
				my($port,$software,$version,$extras,$Pprotocol,$Pport,$Pport_status,$Preason,$Pservice_name,$Pproduct,$Pversion,$Phostname,$Pextrainfo,$PProduct) = '';
				
				#if ($ops == 1) {print "aaaa\n";
			    	if ($sport_cont =~ /protocol="([^"]+)" portid="([^"]+)"><state state="([^"]+)" reason="([^"]+)"/) {
			    		($Pprotocol,$Pport,$Pport_status,$Preason) = ($1,$2,$3,$4);###
			  		}
			  		if ($Pport_status !~ /open/) {
			  			next;
			  		}
			    	push(@extras,$Pport_status.' ('.$Preason.')');	
			    	if ($sport_cont =~ /<service name="([^"]+)"/) {
			    		$Pservice_name = $1;###
			    			
			    		if (in_array($ip.":".$Pport.":".$Pservice_name,@brute_forces) == 0) {
			    			
			    			if ($Pservice_name =~ /ftp/i) {
			    				push(@ftps,$ip.":".$Pport);
			    			}
			    			elsif ($Pservice_name =~ /ssh/i) {
			    				push(@sshs,$ip.":".$Pport);
			    			}
			    			elsif ($Pservice_name =~ /telnet/i) {
			    				push(@telnets,$ip.":".$Pport);
			    			}
			    			elsif ($Pservice_name =~ /http/i) {#print "ooo\n";
			    				push(@webs,$ip.":".$Pport);
			    			}
			    			elsif ($Pservice_name =~ /pop3/i) {
			    				push(@pop3s,$ip.":".$Pport);
			    			}
						elsif ($Pservice_name =~ /netbios/i) {
			    				push(@netbios,$ip.":".$Pport);
			    			}
			
		    				elsif ($Pservice_name =~ /rdp/i) {
		    					push(@rdps,$ip.":".$Pport);
			    			}
			    			elsif ($Pservice_name =~ /ms-sql/i) {
			    				push(@mssqls,$ip.":".$Pport);
			    			}
			    			elsif ($Pservice_name =~ /mysql/i) {
			    				push(@mysqls,$ip.":".$Pport);
			    			}#print "pshato: ".$ip.":".$Pport.":".$Pservice_name."\n";
						push(@brute_forces,$ip.":".$Pport.":".$Pservice_name);#print "\n\n@brute_forces\n\n";
			    		}
			    			
			    	}
			    	if ($sport_cont =~ /product="([^"]+)"/) {
			    		$Pproduct = $1;###
			    	}
			    	if ($sport_cont =~ /version="([^"]+)"/) {
			    		$Pversion = $1;###
			    	}
			
			   	if (length($Pproduct) > 1) {
			    		$PProduct = $Pproduct.' '.$Pversion;
			    		push(@extras,$PProduct);
			    	}
			    		
			    	if ($sport_cont =~ /hostname="([^"]+)"/) {
			    		$Phostname = $1;###
			    		push(@extras,$Phostname);
			    	}
			    	if ($sport_cont =~ /extrainfo="([^"]+)"/) {
			    		$Pextrainfo = $1;###
			    		push(@extras,$Pextrainfo);
			    	}
			    	while ($sport_cont =~ /<script id="([^"]+)" output="([^"]+)"\/>/g) {
			    		my $Pscripts = $1." : ".$2;
			    		#print $Pscripts."\n";
			    		push(@extras,$Pscripts);	
			    	}
			    		
			    	if (length($PProduct) > 0) {
			    		if (length($Pextrainfo) > 0) {
			    			push(@softwares,"|-|".$ip.":".$Pport."|-|".$PProduct." ".$Pextrainfo);
			    		}
			    		else {
			    			push(@softwares,"|-|".$ip.":".$Pport."|-|".$PProduct);
			    		}
			    	}
			    		
			#print "utututtut\n";
				if ($version_null_skip == 0) {#print "iyiyyi\n";
					if (length($Pproduct) > 2) {
						# abbiamo il prodotto .. versione e' * quindi che ci siano o no ce ne fottiamo il cazzo
						$sfou++;
						push(@vuln_to_go_prods,"[PROD]".$Pproduct."[/PROD][VERS]*[/VERS]");
					}
				}
				elsif ($version_null_skip == 1)  {#print "yyyyyyyyy\n";
					if ((length($Pproduct) > 2)&&(length($Pversion) > 0)) {#print "#####\n";
						# abbiamo prodotto e versione .. OK
						$sfou++;
						my $v;
						if (length($Pextrainfo) > 0) {
							$v = $Pversion." ".$Pextrainfo;
						}
						else {
							$v = $Pversion;
						}
							
						#print "[PROD]".$Pproduct."[/PROD][VERS]".$v."[/VERS]\n\n";
						push(@vuln_to_go_prods,"[PROD]".$Pproduct."[/PROD][VERS]".$v."[/VERS]");
					}#else {print "h\n";}
						
				}
					
		   		yprint('<node ID="'.create_random_id().'" TEXT="'.$Pport.'/'.$Pprotocol.' '.$Pservice_name.'">'."\n",3);
			    		
			    	foreach my $e(@extras) {
			   		yprint('<node ID="'.create_random_id().'" TEXT="'.$e.'"/>'."\n",3);
			   	}
			    		
			    	yprint('</node>'."\n",3);
			}
			
			if ($ops =~ /1|2|4/) {
				if ((length($status) > 0)&&(length($count) > 0)) {
					yprint('<node ID="'.create_random_id().'" TEXT="Extraports State:'.$count.' ports are '.$status.'"/>'."\n",3);
				}
			}
		}
		else {
			$port_stram =~ s/FOLDED="AAA"/FOLDED="true"/;
			##yprint($port_stram,3);
			
		}
		
		
		if ($ops =~ /1|2|4/) {
			yprint("</node>\n",3);
			
			if ($content =~ /<osmatch name=/) {
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="Misc">'."\n",3);
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="OS Guess">'."\n",3);
				while ($content =~ /<osmatch name="([^"]+)" accuracy="([^"]+)"/g) {  
					yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$1.' ('.$2.'%)"/>'."\n",3);
				}
				yprint('</node></node>',3);
			}
			
			
		}
		
		
		my $chrt = 0;
		my $chrt1 = 0;
		my @chrt1 = ();
		
		if ($ops =~ /2|4/) {#print "%%%%%%%%%%%% sfou: $sfou\n";
		
			if ($sfou > 0) {#print "dndndnd\n";
				#print @vuln_to_go_prods;#exit;
				if (scalar(@mindmap_vulnerabilities_perhost) > 0) {
					splice(@mindmap_vulnerabilities_perhost,0);
				}
				
				#yprint("[+] Upcoming Softwares/Versions for: $ip\n");
				print "\n\n##: $ip\n";
				foreach my $v(@vuln_to_go_prods) {
					$v =~ /\[PROD\](.+)\[\/PROD\]\[VERS\](.+)\[\/VERS\]/;
					yprint("    $1/$2\n");
				}
				
				
			
				foreach my $i(@vuln_to_go_prods) {#print "\tX: $i\n";
				
					$i =~ /\[PROD\](.+)\[\/PROD\]\[VERS\](.+)\[\/VERS\]/;#print "5555sss: ".$i."\n";
					my($software,$vx) = ($1,$2);
				
					if (in_array($software." > ".$vx,@soft_vers_spid_se) == 0) {
						push(@soft_vers_spid_se,$software." > ".$vx);
				
						# yprint("[+] Do you want to start mining vulnerabilities for:\n    $software/$vx\n[+] Choice (y|n): ");
						# chomp(my $ch = <STDIN>);
						# if ($ch !~ /^n$/) {
							
						# 	&search_start($software,$vx);
						# 	push(@chrt1,$i);#print "scalar: ".scalar(@mindmap_vulnerabilities_perhost)."\n";
						# print "\n\n\n\n\n\n##\n\n@mindmap_vulnerabilities_perhost\n\n##\n\n\n\n\n\n";
						# }
						# else {
						# 	yprint("[+] Skipping, going next !\n");
						# }
					}
					else {
						# means we already searched that software and version ... ora trova un modo per
						#	print "already searched ..\n\n\n";
					}
					$chrt++;
				}
				#print "\n\n\n\n####### FINE merda per questo host .....\n";
			
			
			
			
			
			
				if (scalar(@mindmap_vulnerabilities_perhost) > 0) {#print "aaaaaaaapppppp\n";
					yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="Vulnerabilities()">'."\n",3);
					#print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="Vulnerabilities()">'."\n";
				
					#my $string = "[CVE]".$vars_to_print[2]." ".$vars_to_print[3]."%%%%%".$vars_to_print[4]."%%%%%".$vars_to_print[7]."%%%%%".$vars_to_print[8]."%%%%%".$vars_to_print[12]."%%%%%".$vars_to_print[13]."[/CVE]";
					#push(@mindmap_vulnerabilities_perhost,$string);
				
				
					my $cg = 0;
					foreach my $i(@mindmap_vulnerabilities_perhost) {#print "\tK88888888888888: $i\n";
				
						#print "\n\n%%%%%%%%%%%%%%%%%%%%%%%%%%:$i\n\n";
					
						#my $numb = $chrt1[$cg];
					
						#my $v = $vuln_to_go_prods[$numb];
					
					
						#print "\n\nHFDGFDHJGDFHJFDGHJFDGFDHJGFDHJFDGHJFDGFDHJGFD\n\n";
						#foreach my $i(@vuln_to_go_prods) {
						#	print "D: $i\n";
						#}
					
					
					
						#$v =~ /\[PROD\](.+)\[\/PROD\]\[VERS\](.+)\[\/VERS\]/;
						my $as = $i;
						
						$as =~ s/\[CVE\]/\t[CVE]/g;
						
						$as =~ /^\[AAA\]\[([^\t]+)\/([^\t]+)\]\t\[CVE\]/;
						my($software,$vx) = ($1,$2);
						$as =~ s/\t\[CVE\]/[CVE]/g;
						yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$software.'/'.$vx.'">'."\n",3);
						print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$software.'/'.$vx.'">'."\n";

						#my $a = $i;
						$as =~ s/\[CVE\]/\n\n\[CVE\]/g;
						#(.+)%%%%%(.+)%%%%%(.+)%%%%%(.+)%%%%%(.+)%%%%%(.+)
						while ($as =~ /\[CVE\]([^\n]+)\[\/CVE\]/g) {
						
							my $x = $1;
							$x =~ /^(.+)%%%%%(.+)%%%%%(.+)%%%%%(.+)%%%%%(.+)%%%%%(.+)$/;
						
							#print "#XXXX: $x\n";
							my($a,$b,$c,$d,$e,$f) = ($1,$2,$3,$4,$5,$6);
						
							#$e =~ s/ \|\|\|\|\| /\n/g;
							#$f =~ s/ \|\|\|\|\| /\n/g;
							yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$a.'">'."\n",3);
							print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$a.'">'."\n";
							yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$b.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$b.'"/>'."\n";
							yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$c.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$c.'"/>'."\n";
							yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$d.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$d.'"/>'."\n";
						
							if ($e !~ /0 Exploit/i) {
								#print "\n###UUUUK\n\t$e\nENDUUUKL###\n";
								while ($e =~ /([^\s]+)/g) {
									#print "\t$1\n";
									yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$1.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$1.'"/>'."\n";
							
								}#print "\n######################\n";
							}
							else {
								if ($f =~ /Not available/i) {
									yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="No Exploits available"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="No Exploits available"/>'."\n";
								}
							}
						
							if ($f !~ /Not available/i) {
								#print "\n###UUUUK\n\t$f\nENDUUUKL###\n";
								while ($f =~ /([^\s]+)/g) {
									#print "\t$1\n";
									yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$1.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$1.'"/>'."\n";
							
								}#print "\n######################\n";
							}
							else {
							
							}
							#yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$e.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$e.'"/>'."\n";
							#yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$f.'"/>'."\n",3);print '<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$f.'"/>'."\n";
							#$cg++;
							yprint('</node>',3);
						}
						$cg++;
						yprint('</node>',3);
					
					}
			
			
					yprint('</node>',3);
			
			
				}
				splice(@mindmap_vulnerabilities_perhost,0);
			}
		}
		yprint("</node>\n",3);
		
	}
	
	&create_statistics_mm();
	
	
	yprint("\n[+] Mindmap done: $log_file.mm\n    Open Mindjet MindManager, import the just created file, and Enjoy !\n\n");
	my $foot = "</node></map>\n";
	yprint($foot,3);
	close(MMReport);
	exit(0);
}



sub create_statistics_mm() {
	

	
	#ip:port
	
	
	if ((scalar(@ftps) > 0)||(scalar(@sshs) > 0)||(scalar(@telnets) > 0)||(scalar(@webs) > 0)||(scalar(@pop3s) > 0)||(scalar(@netbios) > 0)||(scalar(@rdps) > 0)||(scalar(@mssqls) > 0)||(scalar(@mysqls) > 0)) {
		yprint('<node FOLDED="false" ID="'.create_random_id().'" TEXT="Overview">'."\n",3);
		
		if (scalar(@ftps) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="FTP('.scalar(@ftps).')">'."\n",3);
			
			foreach my $i(@ftps) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		
		if (scalar(@sshs) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="SSH('.scalar(@sshs).')">'."\n",3);
			
			foreach my $i(@sshs) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		if (scalar(@telnets) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="Telnet('.scalar(@telnets).')">'."\n",3);
			
			foreach my $i(@telnets) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		if (scalar(@webs) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="WWW('.scalar(@webs).')">'."\n",3);
			
			foreach my $i(@webs) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}

		
		if (scalar(@pop3s) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="POP3('.scalar(@pop3s).')">'."\n",3);
			
			foreach my $i(@pop3s) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		if (scalar(@netbios) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="NetBIOS('.scalar(@netbios).')">'."\n",3);
			
			foreach my $i(@netbios) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		if (scalar(@rdps) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="RDP('.scalar(@rdps).')">'."\n",3);
			
			foreach my $i(@rdps) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		if (scalar(@mssqls) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="MS-SQL('.scalar(@mssqls).')">'."\n",3);
			
			foreach my $i(@mssqls) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		if (scalar(@mysqls) > 0) {
			yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="MySQL('.scalar(@mysqls).')">'."\n",3);
			
			foreach my $i(@mysqls) {
				
				yprint('<node FOLDED="true" ID="'.create_random_id().'" TEXT="'.$i.'"/>'."\n",3);
			}
			
			yprint('</node>'."\n",3);
		}
		yprint('</node>'."\n",3);
		
		
		
	}
	else {
		#no services found .. fuck off this statistics
		print "no services\n\n";
	}
	
	
}



sub in_array() {
    my($l,@arr) = @_;
    my $found = 0;
    foreach my $e(@arr) {
        if ($found == 0) {
            if ($e eq $l) {
                $found = 1;
            }
        }
    }
    return $found;
}

sub test_create_logs() {
	my $opt = $_[0];		
	if (!open TEST, '>', 'yminer_testfile') {
		yprint("[-] Can't create test file : $!\n\n");
		exit(0);
	}
	else {
		unlink('yminer_testfile');
		my $ok;
		my $failed = '';
			
			#print "5895895\n";
		if ($opt == 4) {
			$ok = 3;
			
			if (!open TXTReport, '>', 'html_report/'.$log_file.'.txt') {
				$ok--;
				$failed .= 'TXT';
			}
			if (!open HTMLReport, '>', 'html_report/'.$log_file.'.html') {
				$ok--;
				$failed .= 'HTML';
			}
			if (!open MMReport, '>', 'html_report/'.$log_file.'.mm') {
				$ok--;
				$failed .= 'MM';
			}
		}
		elsif ($opt == 3) {
			$ok = 2;
			
			if (!open TXTReport, '>', 'html_report/'.$log_file.'.txt') {
				$ok--;
				$failed .= 'TXT';
			}
			if (!open HTMLReport, '>', 'html_report/'.$log_file.'.html') {
				$ok--;
				$failed .= 'HTML';
			}
		}
		
		elsif (($opt == 2)||($opt == 1)) {
			$ok = 1;#print "ieroioieroerioer: $log_file\n\n";
			if (!open MMReport, '>', 'html_report/'.$log_file.'.mm') {
				$ok--;
				$failed .= 'MM';
			}
		}
			
				
		if ((($opt == 4)&&($ok == 3))||(($opt == 3)&&($ok == 2))||((($opt == 1)||($opt == 2))&&($ok == 1))) {#print "YYYYYY\n";
          
			$file_st = 1;
				
			my $st;
			if ($opt == 4) {
				$str = "HTML, TXT and MindMap reports";
			}
			elsif ($opt == 3) {
				$str = "HTML and TXT reports";
			}
			else {
				$str = "MindMap report";
			}
			
				
			yprint("\n[+] Log(s) File : OK !\n[+] $str will be available after the first complete cycle.\n");
			
			if (($opt == 4)||($opt == 3)) {#print "6rh47fh4\n";
			
				my $text = 	"\n#  -------------------------------------------------------------------------------------------\n".
							"#  yVulnerability Miner v1.0\n".
							"#  gio\n".
							"#  -------------------------------------------------------------------------------------------\n\n\n";
			     	
				# $html -> HEADER - SINGLE ONLY ONE TIME IN ALL REPORT
				$html =	'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//IT"><html><head><title>yVulnerability Miner v1.0 - Report</title>'.
						'<meta http-equiv = "Content-Type" content = "text/html; charset=ISO-8859-1" /><meta name="author" content = "Giovanni"/>'.
						'<meta name="description" content = "yVulnerability Miner v1.0 HTML Report - Developed by Me"/>'.
						'<meta name="keywords" content = "vulnerability,CVE,cvedetails,securityfocus,metasploit,code execution,vulnerability assestment,risk,web app,IT security"/>'.
						'<link rel="shortcut icon" href="./graphic/favicon.ico" type="image/x-icon"/><script type="text/javascript">function element(id) {if (document.getElementById("CVE_container_"+id)) {'.
						'if (document.getElementById("CVE_container_"+id).style.display == "none"){document.getElementById("CVE_container_"+id).style.display = "block";}else {document.getElementById'.
						'("CVE_container_"+id).style.display = "none";}}}</script><style type="text/css" media="all">body {margin: auto;color:white;direction:ltr;font-family:"lucida grande",tahoma,ver'.
						'dana,arial,"sans-serif";overflow-y: scroll;background-color: rgb(20,20,24);}.crowBS a:link, a:visited, a:active {text-decoration: none;color: yellow;}a.nspl:link, a:visited, a:active {'.
						'text-decoration: none;color: #148FCC;}img {border: none;margin: 0px;}#all {background-color: rgb(20,20,24);display: block;height: auto;width: 904px;margin: auto;border: none;back'.
						'ground-repeat:repeat-y;background-image: url(./graphic/headerZZ.png);}#header {background-image: url(./graphic/headerA.png);background-repeat: no-repeat;width: 904px;height: 93px;border: none;}'.
						'#logo_l {float: left;width: 209px;background-image: url(./graphic/banner.png);background-repeat: no-repeat;height: 30px;margin: 10px 0px 0px 20px;border: none;}'.
						'#logo_r {float: right;border: none;}#logo_r p{font-size: 12px;padding-right: 25px;}#content {height: auto;}.main_element_title {height: 25px;width : 850px;background-color: black;margin-bottom: 10px;}'.
						'.main_element_title p {margin: 0;font-weight: bold;font-size: 13px;padding: 5px 0px 0px 4px;}.main_element_title_l {float: left;}.main_element_title_r {float:right;padding: 5px 5px 0px 0px;}'.
						'.search_summary {width:850px;height:auto;margin-bottom: 10px;}.summary_table {color: white;}.srowA {height: 20px;width: 150px;font-size :10px;font-weight: bold;padding-left: 5px;}'.
						'.srowB {height: 20px;width: auto;padding-left: 5px;font-size :10px;}.srowBB {height: 20px;width: 300px;padding-left: 5px;font-size :10px;font-weight: bold;color: red;}'.
						'.cve_detail {width:850px;height:auto;margin-bottom: 10px;padding-top: 10px;border-top: 1px solid white;}.crowA {height: auto;width: 120px;font-size :10px;font-weight: bold;padding-left: 5px;}'.
						'.crowB {height: auto;width: auto;padding-left: 5px;font-size :10px;}.crowBB {height: auto;width: auto;padding-left: 5px;font-size :10px;color: #0066FF;font-weight: bold;}'.
						'.spdddl {color: red;}#footer {background-color: black;height: auto;margin-top: 40px;}#footer p {font-size: 11px;padding: 10px 5px 10px 5px;text-align: center;}'.
						'.seach_main_element {height: auto;width:850px;margin-left: 27px;margin-bottom: 20px;}</style></head><body><div id="all"><div id="header"><div id="logo_l"></div><div id="logo_r">'.
						'<p>yVulnerability Miner v1.0 - Report</p></div></div><div id="content">';
	               	
	               	
				# $foot -> FOOTER - SINGLE ONLY ONE TIME IN ALL REPORT
				$foot = '</div><div id="footer"><p>ylabs ALL RIGHTS RESERVED.</br>'.
						'yVulnerability Miner v1.0 - Developed by Me</p></div></div></body></html>';
		     	
				$tr_str = ' onmouseover="this.style.backgroundColor=\'black\'; this.style.color=\'white\';" onmouseout="this.style.backgroundColor=\'\';this.style.color=\'\';"';
		     	
				yprint($text,1);
				yprint($html.$foot,2);
				
				if ($opt == 4) {
					my $head = '<?xml version="1.0" ?><map version="0.7.1"><node FOLDED="false" ID="'.create_random_id().'" TEXT="NMAP RESULTS">'."\n";
					my $foot = "</node></map>\n";
					yprint('<?xml version="1.0" ?><map version="0.7.1"><node FOLDED="false" ID="'.create_random_id().'" TEXT="NMAP RESULTS">'."\n",3);
				}
				
			}
			else {#print "464v 4v4v4v4bn\n";
				if (($opt == 1)||($opt == 2)) {#print "degrhrjrjr\n";
					my $head = '<?xml version="1.0" ?><map version="0.7.1"><node FOLDED="false" ID="'.create_random_id().'" TEXT="NMAP RESULTS">'."\n";
					my $foot = "</node></map>\n";
					yprint('<?xml version="1.0" ?><map version="0.7.1"><node FOLDED="false" ID="'.create_random_id().'" TEXT="NMAP RESULTS">'."\n",3);		
				}
			}
		}
		else {
			if ($failed =~ /^TXT$/) {
				yprint("[-] Can't create TXT report !\n\n");
			}
			elsif ($failed =~ /^HTML$/) {
				yprint("[-] Can't create HTML report !\n\n");
			}
			elsif ($failed =~ /^MM$/) {
				yprint("[-] Can't create MM report !\n\n");
			}
			else {
				yprint("[-] Can't create reports !\n\n");
			}
			exit(0);
		}
	}
}

sub remove_arrays() {
	splice(@partial_matches,0);
	splice(@no_matches,0);
	splice(@partial_urls,0);
	splice(@no_urls,0);
	splice(@vuln_to_go,0);
}

sub encode() {
	my $str = $_[0];
	$str =~ s/%/%25/g;
   	$str =~ s/ /\+/g;
   	$str =~ s/'/%27/g;
   	$str =~ s/!/%21/g;
   	return($str);
}

# LOL : Using Perl defaults UA, this was the HTML response from CVEdetails:

# <html xmlns="http://www.w3.org/1999/xhtml">
# <head>
# </head>
# <body>
# 	 <h1>
# 		 Please stop scanning the site... Go out, do something useful
# 	 </h1>
# </body>
# </html>

# UA filter: too hard to change it uh ?


sub request() {
	my($link,$e_time) = @_;#print "e_time: $e_time\n";
	my($e_count,$meta,$location);
	
	
	
	
	
	# from google, typing as search: securityfocus.com/bid/30560/
	# clicking on securityfocus link .. you reach securityfocus with this referrer:
	# Referer: http://www.google.it/url?sa=t&source=web&cd=1&ved=0CCAQFjAA&url=http%3A%2F%2Fwww.securityfocus.com%2Fbid%2F30560&rct=j&q=securityfocus.com
	#		 %2Fbid%2F30560%2F&ei=hGBcTruyDuStsAKYibU7&usg=AFQjCNFFT_-wzFRyB9kjI9KUgqgMySSuVg
	
	# then .. from inside the BID .. to surf through the pages discuss solutions exploit etc .. send the refferer:
	# Referer: http://www.securityfocus.com/bid/30560

	
	
	
	
	
	
	my @ua = (
				'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6',
				'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)',
				'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
				'Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.1; .NET CLR 1.1.4322)',
				'Opera/9.20 (Windows NT 6.0; U; en)',
				'Opera/9.00 (Windows NT 5.1; U; en)',
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.50',
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.0',
				'Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.1) Opera 7.02 [en]',
				'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5) Gecko/20060127 Netscape/8.1',
				'Konqueror/3.0-rc4; (Konqueror/3.0-rc4; i686 Linux;;datecode)',
				'Mozilla/5.0 (Macintosh; U; PPC Mac OS X; en-US) AppleWebKit/125.4 (KHTML, like Gecko, Safari) OmniWeb/v563.15',
				'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:5.0.1) Gecko/20100101 Firefox/5.0.1'
			);
			
	my $user_agent_i = rand($#ua);
	
	if (length($e_time) == 0) {
		$e_count = 0;
	}
	else {
		$e_count = $e_time;
	}
	
	my $ua  = LWP::UserAgent->new;
	$ua->agent($ua[$user_agent_i]); # <--  Rand, Ok
	#$ua->agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:5.0.1) Gecko/20100101 Firefox/5.0.1');
	$ua->timeout(3);
	#$ua->show_progress(1);
	$requests_performed_block_count++;
	if ($requests_performed_block_count % 5 == 0) {
		sleep(1);
	}
	
	my $response = $ua->get($link);
	my $res = "";
	
	if ($response->is_success) {
		$res = $response->content;
	}
	else {
		yprint("[!] Problem in getting response from: $link\n    Sleeping for 3 seconds before next request!\n");
		#die $response->status_line;
		# try again
		if ($e_count < 2) {
			sleep(3);
			$res = request($link,++$e_count);
		}
		else {
			# Too many epic http fails .. exit -.-
			#print $response->status_line."\n";
			yprint("    ".$response->status_line."\n[-] Returning null response !\n");
		}
	}
	return($res);
}

sub yprint() {
	my($text,$opt) = @_;

	if ($opt == 3) {
		print MMReport $text;
	}
	elsif ($opt == 2) {
		close(HTMLReport);
		open(HTMLReport, '>', $log_file.'.html');
		print HTMLReport $text;
	}
	elsif ($opt == 1) {
		print TXTReport $text;
	}
	else {
		print $text;
	}
}

sub safe_close() {
	close(FILE);
	&yprint("\n[!] Quitted ! Bye!\n");
	exit(0);
}

sub fun_return() {
	my $var = $_[0];
	#if (($var == 1)||($var == 2)) {
	#	return($var);
	#}
	#else {
	#	return(0);
	#}
	return($var);
}

sub create_random_id {
	my @chars_length = ('8','4','4','4','12');
	my @chars = ('A'..'Z','0'..'9');
	my $tot_str;
	foreach my $l(@chars_length) {
		my $rstr;
		foreach (1..$l) {
			$rstr .= $chars[rand @chars];
		}
		$tot_str .= $rstr."-";
	}
	$tot_str =~ s/-$//;
	
	my $r = &in_array($tot_str,@randoms_id);
	if ($r == 1) {
		create_random_id();
	}
	else {
		push(@randoms_id,$tot_str);
	}
	return($tot_str);
}

sub ybanner() {
	print 	"\n".
			"-----------------------------------------\n".
			"              vMiner v1.0\n".
			"-----------------------------------------\n\n";
}


# EOF - Osirys - Y