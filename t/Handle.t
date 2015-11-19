use strict;
use warnings;

use Test::Spec;
use Scalar::Util qw(weaken);

use Linux::Netfilter::Conntrack qw(:constants);

describe "Linux::Netfilter::Conntrack::Handle" => sub
{
	it "can be constructed" => sub
	{
		my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
		isa_ok($handle, "Linux::Netfilter::Conntrack::Handle");
	};

	it "holds a reference to the conntrack callback" => sub
	{
		my $foo;
		my $callback = sub { $foo };

		my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
		$handle->ct_callback_register(NFCT_T_ALL, $callback);

		weaken($callback);

		# The callback refcount will drop to 0 and become undef if the
		# XS code isn't also holding a reference.
		ok(defined $callback);
	};

	it "releases the conntrack callback after ct_callback_unregister is called" => sub
	{
		my $foo;
		my $callback = sub { $foo };

		my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
		$handle->ct_callback_register(NFCT_T_ALL, $callback);
		$handle->ct_callback_unregister();

		weaken($callback);

		ok(!defined $callback);
	};

	it "releases the conntrack callback after being destroyed" => sub
	{
		my $foo;
		my $callback = sub { $foo };

		{
			my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
			$handle->ct_callback_register(NFCT_T_ALL, $callback);
		}

		weaken($callback);

		ok(!defined $callback);
	};

	it "doesn't allow registering two conntrack callbacks" => sub
	{
		my $foo;
		my $callback = sub { $foo };

		my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
		$handle->ct_callback_register(NFCT_T_ALL, $callback);

		trap {
			$handle->ct_callback_register(NFCT_T_ALL, $callback);
		};

		like($trap->die(), qr/Callback already registered/);
	};

	it "allows registering a new conntrack callback after unregistering the old" => sub
	{
		my $foo;
		my $callback = sub { $foo };

		my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);
		$handle->ct_callback_register(NFCT_T_ALL, $callback);
		$handle->ct_callback_unregister();

		trap {
			$handle->ct_callback_register(NFCT_T_ALL, $callback);
		};

		ok(!defined $trap->die());
	};

	it "doesn't try unregistering a nonexistant conntrack callback" => sub
	{
		my $handle = Linux::Netfilter::Conntrack::Handle->new(NFNL_SUBSYS_CTNETLINK, 0);

		trap {
			$handle->ct_callback_unregister();
		};

		like($trap->die(), qr/No callback registered/);
	};
};

runtests unless caller;

1;
