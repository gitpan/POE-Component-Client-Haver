#!/usr/bin/perl
use Module::Build;
my $build = Module::Build->new(
	module_name        => 'POE::Component::Client::Haver',
	dist_version_from  => 'lib/POE/Component/Client/Haver.pm',
	dist_author        => 'Bryan Donlan <bdonlan@bd-home-comp.no-ip.org>',
	license => 'gpl',
	requires => {
		'perl'           => '5.6.1',
		POE              => 0.27,
		Haver            => 0.06,
		'Haver::Client'  => 0.06,
		'Digest::SHA1'   => 2.01,
		'Data::Dumper'   => 2.121,
	},
	create_makefile_pl => 'passthrough',
);
$build->create_build_script;
