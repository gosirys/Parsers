#!/usr/bin/perl

# gio master of cazzi
# cazzolabs

open(FILE, '<', 'uuuu.xml');

$input_file_content;
%software = ();

while (my $a = <FILE>) {
	$a =~ s/\n//g;
	if ($a =~ /<host /) {
		$a =~ s/<host /\n\n<host /;
	}
	if ($a =~ /<\/host>/) {
		$a =~ s/<\/host>/<\/host>\n\n/;
	}
	$input_file_content .= $a;
}

while ($input_file_content =~ /<host ([^\n]+)<\/host>/g) {
	my $cont = $1;
	$cont =~ s/\n//g;
	if ($cont =~ /<port /) {
		$cont =~ s/<port /\n\n<port /g;
	}
	if ($cont =~ /<\/port>/) {
		$cont =~ s/<\/port>/<\/port>\n\n/g;
	}

	while ($cont =~ /<port ([^\n]+)<\/port>/g) {
		my $cont2 = '<port '.$1.'</port>';

		
		my($product,$version) = '';

		if ($cont2 =~ /product="([^"]+)"/i) {
			$product = $1;
		}

		if ($cont2 =~ /version="([^"]+)"/i) {
			$version = $1;
		}

		$str = $product." ".$version;
		if (length($str) > 2) {

			if (!(exists($software{$str}))) {
				$software{$str} = 'a';
			}
		}
	}
}

while ( my ($key, $value) = each(%software) ) {
	print $key."\n";
}

close(FILE);