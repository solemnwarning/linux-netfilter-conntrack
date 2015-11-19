use strict;
use warnings;

use Module::Build;

if($^O ne "linux")
{
	die("No support for OS");
}

Module::Build->new(
	dist_name     => "Linux-Netfilter-Conntrack",
	dist_version  => "0.01",
	dist_abstract => "Linux conntrack (libnetfilter_conntrack) wrapper",
	dist_author   => [ "Daniel Collins <daniel.collins\@smoothwall.net>" ],
	
	module_name => "Linux::Netfilter::Conntrack",
	license     => "perl",
	
	build_requires => {
		"Module::Build"  => "0.2806",
		"ExtUtils::H2PM" => "0.03",
	},
	
	include_dirs       => [ "./" ],
	extra_linker_flags => [ "-lnetfilter_conntrack" ],
)->create_build_script();
