/* */

/* XXXrcd: Put in a copyright */

#ifdef	HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <string.h>

#include "libknc.h"
#include "private.h"

void
knc_authenticate(knc_ctx ctx)
{

	if (!ctx)
		return;

	while (!knc_is_authenticated(ctx) && !knc_error(ctx)) {
		run_loop(ctx);
	}
}

static size_t
reads_get_buf(knc_ctx ctx, void *buf, size_t len)
{
	size_t	 ret;
	size_t	 total;
	void	*tmp;

	total = 0;
	for (;;) {
		ret = knc_get_obuf(ctx, KNC_DIR_RECV, &tmp, len - total);

		if (ret == 0)
			break;

		memcpy((char *)buf + total, tmp, ret);
		knc_drain_buf(ctx, KNC_DIR_RECV, ret);
		total += ret;

		if (total == len)
			break;
	}

	return total;
}

static ssize_t
internal_read(knc_ctx ctx, void *buf, size_t len, int full)
{
	ssize_t	 ret;
	ssize_t	 total;
	int	 fillerr;

	if (!ctx) {
		errno = EBADF;
		return -1;
	}

	/*
	 * We attempt to return data before we initiate a
	 * read because the read may block and we shouldn't
	 * block if there is data available to return.
	 */

	total = reads_get_buf(ctx, buf, len);

	if ((!full && total > 0) || total == (ssize_t)len)
		return total;

	/*
	 * If the socket is closed (or half closed in the direction
	 * we need), then we return 0 indicating EOF.
	 */

	/* XXXrcd: bad check for EOF, not the right place? */
	if (total == 0 && knc_eof(ctx))
		return 0;

	/*
	 * If the socket is blocking: flush output before reading.
	 * The goal here is to make standard request response protocols
	 * used in blocking mode more likely to work.  We only perform
	 * the flush before we attempt an actual read which is why this
	 * code is below that which comes above.
	 */
	if (!knc_get_opt(ctx, KNC_SOCK_NONBLOCK))
		knc_flush(ctx, KNC_DIR_SEND, (size_t)-1);

	for (;;) {
		while (!knc_need_input(ctx, KNC_DIR_SEND)) {
			fillerr = knc_flush(ctx, KNC_DIR_SEND, 0);
			if (fillerr) {
				errno = fillerr;
				return -1;
			}
		}

		fillerr = knc_fill(ctx, KNC_DIR_RECV);

		switch (fillerr) {
		case 0:
			/* mmm, no error, let's go. */
			break;

#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
		case EAGAIN:
			if (knc_get_opt(ctx, KNC_SOCK_NONBLOCK)) {
				errno = fillerr;
				return -1;
			}
			/*
			 * XXXrcd: really this should be an error if we
			 *         are in blocking mode as why would we
			 *         get this unless someone has naughtily
			 *         lied to us?  At least, if this is going
			 *         to occur, we should poll(2).
			 */
			break;

		default:
			errno = fillerr;
			return -1;
		}

		/* XXXrcd: bad place to check for EOF, I think. */
		if (knc_eof(ctx))
			/* XXXrcd: double check this idea... */
			break;

		ret = reads_get_buf(ctx, (char *)buf + total, len - total);
		total += ret;
		if ((!full && total > 0) || total == (ssize_t)len)
			break;
	}

	return total;
}

ssize_t
knc_read(knc_ctx ctx, void *buf, size_t len)
{

	return internal_read(ctx, buf, len, 0);
}

ssize_t
knc_fullread(knc_ctx ctx, void *buf, size_t len)
{

	return internal_read(ctx, buf, len, 1);
}

ssize_t
knc_write(knc_ctx ctx, const void *buf, size_t len)
{
	ssize_t	ret;

	if (!ctx) {
		errno = EBADF;
		return -1;
	}

	if (knc_error(ctx)) {
		errno = EIO;
		return -1;
	}

#if 0	/* XXXrcd: FIX THIS! */
	if ((ctx->open & OPEN_WRITE) == 0) {
		errno = EPIPE;
		return -1;
	}
#endif

	ret = knc_put_buf(ctx, KNC_DIR_SEND, buf, len);

	/* XXXrcd: I'm abusing sendinbufsiz here, this isn't good. */
	if (!knc_need_input(ctx, KNC_DIR_SEND))
		knc_flush(ctx, KNC_DIR_SEND, 0);

	return ret;
}
