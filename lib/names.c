/* Mechanism-owned name operations. No GSS handles cross a provider boundary. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "libknc.h"
#include "private.h"

/* Local-account extensions supplied by both supported GSS providers. */
extern int gss_userok(gss_name_t, const char *);
extern OM_uint32 gss_localname(OM_uint32 *, gss_name_t, gss_OID,
    gss_buffer_t);

static gss_name_t
initiator(knc_ctx ctx)
{
        if (!ctx || !knc_is_authenticated(ctx)) {
                errno = EINVAL;
                return GSS_C_NO_NAME;
        }
        return knc_get_client(ctx);
}

int
knc_userok(knc_ctx ctx, const char *user)
{
        gss_name_t name = initiator(ctx);
        if (name == GSS_C_NO_NAME || !user || !*user) {
                errno = EINVAL;
                return -1;
        }
        return gss_userok(name, user) == 1;
}

static int
render(knc_ctx ctx, int local, char **result, size_t *length)
{
        gss_buffer_desc buffer = GSS_C_EMPTY_BUFFER;
        gss_name_t name = initiator(ctx);
        OM_uint32 major, minor;
        char *copy;

        if (!result || !length) {
                errno = EINVAL;
                return -1;
        }
        *result = NULL;
        *length = 0;
        if (name == GSS_C_NO_NAME) {
                errno = EINVAL;
                return -1;
        }
        if (local)
                major = gss_localname(&minor, name, knc_get_ret_mech(ctx), &buffer);
        else
                major = gss_display_name(&minor, name, &buffer, NULL);
        if (major != GSS_S_COMPLETE) {
                /* A display failure must not poison an authenticated stream. */
                if (local)
                        knc_gss_error(ctx, major, minor, "gss_localname");
                gss_release_buffer(&minor, &buffer);
                errno = EINVAL;
                return -1;
        }
        if (buffer.length > 65536 || (buffer.length && !buffer.value)) {
                gss_release_buffer(&minor, &buffer);
                errno = EOVERFLOW;
                return -1;
        }
        copy = malloc(buffer.length + 1);
        if (!copy) {
                gss_release_buffer(&minor, &buffer);
                errno = ENOMEM;
                return -1;
        }
        if (buffer.length)
                memcpy(copy, buffer.value, buffer.length);
        copy[buffer.length] = '\0';
        *length = buffer.length;
        *result = copy;
        gss_release_buffer(&minor, &buffer);
        return 0;
}

int knc_localname(knc_ctx ctx, char **name, size_t *len)
{ return render(ctx, 1, name, len); }
int knc_display_name(knc_ctx ctx, char **name, size_t *len)
{ return render(ctx, 0, name, len); }
void knc_free_name(char *name)
{ free(name); }
