/* */

OM_uint32
gss_wrap(OM_uint32 *min, gss_const_ctx_id_t ctx, int conf_req_flag,
	 gss_qop_t qop_req, const gss_buffer_t in, int *conf_state,
	 gss_buffer_t out)
{
	uint32_t	len;

	len = (uint32_t)in->length;

	if (len > SIZE_MAX - sizeof(len))
		return GSS_S_FAILURE;
	out->value = malloc(len + sizeof(len));
	out->length = len + sizeof(len);
	memcpy((char *)out->value + sizeof(len), in->value, len);
	len = htonl(len);
	memcpy(out->value, &len, sizeof(len));
	return 0;
}

OM_uint32
gss_unwrap(OM_uint32 *min, gss_const_ctx_id_t ctx, const gss_buffer_t in,
	   gss_buffer_t out, int *conf_state, gss_qop_t *qop_state)
{
	uint32_t	len;

	memcpy(&len, in->value, sizeof(len));
	len = ntohl(len);

	out->value = malloc(len);
	out->length = len;
	memcpy(out->value, (char *)in->value + sizeof(len), len);
	return 0;
}
