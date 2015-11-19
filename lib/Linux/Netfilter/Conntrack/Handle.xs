#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

struct perl_nfct_handle
{
	struct nfct_handle *handle;

	CV *ct_callback;
};

static int _ct_callback_proxy(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
	SV *callback_func = (SV*)(data);

	SV *cb_arg_type = sv_2mortal(newSViv(type));

	/* Make a copy of the nf_conntrack structure which can persist after
	 * this function returns in case the Perl callback wants to hold onto
	 * the reference.
	*/

	struct nf_conntrack *ct_copy = nfct_clone(ct);
	if(ct_copy == NULL)
	{
		croak("nfct_clone: %s", strerror(errno));
	}

	SV *cb_arg_ct = sv_2mortal(newSV(0));
	sv_setref_pv(cb_arg_ct, "Linux::Netfilter::Conntrack::Connection", ct_copy);

	dSP;

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(cb_arg_type);
	XPUSHs(cb_arg_ct);
	PUTBACK;

	int ret_count = call_sv(callback_func, G_SCALAR);

	SPAGAIN;

	SV *ret_sv;
	int ret;

	if(!(ret_count == 1          /* Perl sub returned 1 SV */
		&& (ret_sv = POPs)   /* Pop it off the stack */
		&& SvIOK(ret_sv)     /* Can be coerced to an integer */
		&& ((ret = SvIV(ret_sv)) == NFCT_CB_STOP || ret == NFCT_CB_CONTINUE)))
	{
		warn("Callback didn't return NFCT_CB_STOP or NFCT_CB_CONTINUE");
		ret = NFCT_CB_CONTINUE;
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return ret;
}

static void *_get_query_data(enum nf_conntrack_query qt, SV *data_sv, uint8_t *u8buf)
{
	switch(qt)
	{
		case NFCT_Q_CREATE:
		case NFCT_Q_UPDATE:
		case NFCT_Q_DESTROY:
		case NFCT_Q_GET:
		case NFCT_Q_CREATE_UPDATE:
			/* TODO: Can I defer to the typemap? */
			if(!(sv_isobject(data_sv)
				&& sv_derived_from(data_sv, "Linux::Netfilter::Conntrack::Connection")
				&& SvTYPE(SvRV(data_sv)) == SVt_PVMG))
			{
				croak("Invalid data, pass a Linux::Netfilter::Conntrack::Connection object for query type %d", (int)(qt));
			}

			return (void*)(SvIV((SV*)SvRV(data_sv)));

		case NFCT_Q_FLUSH:
		case NFCT_Q_DUMP:
		case NFCT_Q_DUMP_RESET:
			/* These ones take a uint8_t protocol family. */

			if(!SvIOK(data_sv) || SvIV(data_sv) < 0 || SvIV(data_sv) > UINT8_MAX)
			{
				croak("Invalid data, pass a protocol number (0-255) for query type %d", (int)(qt));
			}

			*u8buf = SvIV(data_sv);
			return u8buf;

		default:
			croak("Unknown query type %d", (int)(qt));
	};
}

MODULE = Linux::Netfilter::Conntrack::Handle	PACKAGE = Linux::Netfilter::Conntrack::Handle

struct perl_nfct_handle* new(const char *class, uint8_t subsys_id, unsigned subscriptions)
	CODE:
		Newxz(RETVAL, 1, struct perl_nfct_handle*);

		RETVAL->handle = nfct_open(subsys_id, subscriptions);
		if(RETVAL == NULL)
		{
			int err = errno;
			Safefree(RETVAL);

			croak("nfct_open: %s", strerror(err));
		}
	OUTPUT:
		RETVAL

void DESTROY(struct perl_nfct_handle *self)
	CODE:
		if(nfct_close(self->handle) == -1)
		{
			warn("nfct_close: %s", strerror(errno));
		}

		if(self->ct_callback != NULL)
		{
			SvREFCNT_dec(self->ct_callback);
		}

		Safefree(self);

int fileno(struct perl_nfct_handle *self)
	CODE:
		RETVAL = nfct_fd(self->handle);

	OUTPUT:
		RETVAL

void ct_callback_register(struct perl_nfct_handle *self, enum nf_conntrack_msg_type type, CV *cb)
	CODE:
		if(self->ct_callback != NULL)
		{
			croak("Callback already registered, call callback_unregister first");
		}

		if(nfct_callback_register(self->handle, type, &_ct_callback_proxy, (void*)(cb)) == -1)
		{
			croak("nfct_callback_register: %s", strerror(errno));
		}

		SvREFCNT_inc(cb);
		self->ct_callback = cb;

void ct_callback_unregister(struct perl_nfct_handle *self)
	CODE:
		if(self->ct_callback == NULL)
		{
			croak("No callback registered");
		}

		nfct_callback_unregister(self->handle);

		SvREFCNT_dec(self->ct_callback);
		self->ct_callback = NULL;

void send(struct perl_nfct_handle *self, enum nf_conntrack_query qt, SV *data_sv)
	CODE:
		uint8_t u8buf;
		void *data = _get_query_data(qt, data_sv, &u8buf);

		if(nfct_send(self->handle, qt, data) == -1)
		{
			croak("nfct_send: %s", strerror(errno));
		}

int catch(struct perl_nfct_handle *self)
	CODE:
		RETVAL = nfct_catch(self->handle);
		if(RETVAL == -1)
		{
			croak("nfct_catch: %s", strerror(errno));
		}

	OUTPUT:
		RETVAL

void query(struct perl_nfct_handle *self, enum nf_conntrack_query qt, SV *data_sv)
	CODE:
		uint8_t u8buf;
		void *data = _get_query_data(qt, data_sv, &u8buf);

		if(nfct_query(self->handle, qt, data) == -1)
		{
			croak("nfct_query: %s", strerror(errno));
		}
