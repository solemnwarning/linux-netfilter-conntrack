use strict;
use warnings;

use Test::Spec;
use Config;
use Scalar::Util qw(refaddr);
use Socket qw(IPPROTO_TCP IPPROTO_ICMP);

use Linux::Netfilter::Conntrack qw(:constants);

# Get the host endianness for testing the byte order things.
my $is_be = ($Config{byteorder} =~ m/4321/);

describe "Linux::Netfilter::Conntrack::Connection" => sub
{
	it "can be constructed" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();
		isa_ok($ct, "Linux::Netfilter::Conntrack::Connection");
	};

	# Test storing, fetching and unsetting each type of attribute

	it "can store and fetch orig_ipv4_src" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		# TODO: Don't depend on a particular IP address string format.

		$ct->set_orig_ipv4_src("192.168.0.1");
		is($ct->get_orig_ipv4_src(), "192.168.0.1");
	};

	it "can unset orig_ipv4_src" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_ipv4_src("192.168.0.1");
		$ct->unset_orig_ipv4_src();
		is($ct->get_orig_ipv4_src(), undef);
	};

	it "can store and fetch orig_ipv6_src" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		# TODO: Don't depend on a particular IP address string format.

		$ct->set_orig_ipv6_src("2001::FFFF");
		like($ct->get_orig_ipv6_src(), qr/^2001::ffff$/i);
	};

	it "can unset orig_ipv6_src" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_ipv6_src("2001::FFFF");
		$ct->unset_orig_ipv6_src();
		is($ct->get_orig_ipv6_src(), undef);
	};

	it "can store orig_port_src" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_port_src(50_000);
		is($ct->get_orig_port_src(), 50_000);
	};

	it "can unset orig_port_src" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_port_src(50_000);
		$ct->unset_orig_port_src();
		is($ct->get_orig_ipv4_src(), undef);
	};

	it "can store icmp_type" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_icmp_type(8);
		is($ct->get_icmp_type(), 8);
	};

	it "can unset icmp_type" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_icmp_type(8);
		$ct->unset_icmp_type();
		is($ct->get_icmp_type(), undef);
	};

	it "can store and fetch timeout" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_timeout(8);
		is($ct->get_timeout(), 8);
	};

	it "can unset timeout" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_timeout(8);
		$ct->unset_timeout();
		is($ct->get_timeout(), undef);
	};

	it "can store and fetch helper_name" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_helper_name("unmutable");
		is($ct->get_helper_name(), "unmutable");
	};

	it "can unset helper_name" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_helper_name("unmutable");
		$ct->unset_helper_name();
		is($ct->get_helper_name(), undef);
	};

	# Test each of the things implemented using the "filthy" functions in
	# case they cause a segfault or other nastyness.

	describe "can store and fetch orig_counter_packets" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_counter_packets(1234);
		is($ct->get_orig_counter_packets(), 1234);
	};

	describe "can unset orig_counter_packets" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_counter_packets(1234);
		$ct->unset_orig_counter_packets();
		is($ct->get_orig_counter_packets(), undef);
	};

	describe "can store and fetch repl_counter_packets" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_repl_counter_packets(5678);
		is($ct->get_repl_counter_packets(), 5678);
	};

	describe "can unset repl_counter_packets" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_repl_counter_packets(5678);
		$ct->unset_repl_counter_packets();
		is($ct->get_repl_counter_packets(), undef);
	};

	describe "can store and fetch orig_counter_bytes" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_counter_bytes(4321);
		is($ct->get_orig_counter_bytes(), 4321);
	};

	describe "can unset orig_counter_bytes" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_counter_bytes(4321);
		$ct->unset_orig_counter_bytes();
		is($ct->get_orig_counter_bytes(), undef);
	};

	describe "can store and fetch repl_counter_bytes" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_repl_counter_bytes(8765);
		is($ct->get_repl_counter_bytes(), 8765);
	};

	describe "can unset repl_counter_bytes" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_repl_counter_bytes(8765);
		$ct->unset_repl_counter_bytes();
		is($ct->get_repl_counter_bytes(), undef);
	};

	describe "can store and fetch timestamp_start" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_timestamp_start(1234);
		is($ct->get_timestamp_start(), 1234);
	};

	describe "can unset timestamp_start" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_timestamp_start(1234);
		$ct->unset_timestamp_start();
		is($ct->get_timestamp_start(), undef);
	};

	describe "can store and fetch timestamp_stop" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_timestamp_stop(1234);
		is($ct->get_timestamp_stop(), 1234);
	};

	describe "can unset timestamp_stop" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_timestamp_stop(1234);
		$ct->unset_timestamp_stop();
		is($ct->get_timestamp_stop(), undef);
	};

	it "can be formatted as a string (snprintf method)" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		# Populate just enough fields to get something out of the
		# nfct_snprintf function.

		$ct->set_orig_l4proto(IPPROTO_TCP);
		$ct->set_orig_port_src(56789);
		$ct->set_orig_port_dst(80);

		my $got = $ct->snprintf(NFCT_T_UPDATE, NFCT_O_DEFAULT, 0);

		like($got, qr/\[UPDATE\]/);
		like($got, qr/dport=80/);
		like($got, qr/sport=56789/);
	};

	it "can be formatted as a string (stringify)" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		# Populate just enough fields to get something out of the
		# nfct_snprintf function.

		$ct->set_orig_l4proto(IPPROTO_TCP);
		$ct->set_orig_port_src(56789);
		$ct->set_orig_port_dst(80);

		my $got = "$ct";

		like($got, qr/dport=80/);
		like($got, qr/sport=56789/);
	};

	it "can be copied" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		$ct->set_orig_l4proto(IPPROTO_ICMP);

		my $ctc = $ct->clone();

		isa_ok($ctc, "Linux::Netfilter::Conntrack::Connection");
		isnt(refaddr($ctc), refaddr($ct));

		is($ctc->get_orig_l4proto(), IPPROTO_ICMP);
	};

	it "can be exported" => sub
	{
		my $ct = Linux::Netfilter::Conntrack::Connection->new();

		# Test we can export one of each type of field.
		$ct->set_orig_ipv4_src("192.168.0.1");
		$ct->set_orig_ipv6_dst("2001::1");
		$ct->set_orig_port_src(1234);
		$ct->set_icmp_type(8);
		$ct->set_timeout(5678);
		$ct->set_orig_counter_packets(4);

		my $got = $ct->export();

		cmp_deeply($got, {
			orig_ipv4_src        => "192.168.0.1",
			orig_ipv6_dst        => "2001::1",
			orig_port_src        => 1234,
			icmp_type            => 8,
			timeout              => 5678,
			orig_counter_packets => 4,
		});
	};

	it "can be re-constructed from an export" => sub
	{
		# Test we can import one of each type of field.
		my $data = {
			orig_ipv4_src        => "192.168.0.1",
			orig_ipv6_dst        => "2001::1",
			orig_port_src        => 1234,
			icmp_type            => 8,
			timeout              => 5678,
			orig_counter_packets => 4,
		};

		my $ct = Linux::Netfilter::Conntrack::Connection->new_from_export($data);

		is($ct->get_orig_ipv4_src(),        "192.168.0.1");
		is($ct->get_orig_ipv6_dst(),        "2001::1");
		is($ct->get_orig_port_src(),        1234);
		is($ct->get_icmp_type(),            8);
		is($ct->get_timeout(),              5678);
		is($ct->get_orig_counter_packets(), 4);
	};
};

runtests unless caller;

1;
