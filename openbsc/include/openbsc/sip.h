#ifndef _SIP_H
#define _SIP_H

#include <openbsc/sip_client.h>
#include <openbsc/reg_proxy.h>
#include <osip2/osip.h>

int tx_sip_register(struct sip_client *sip_client, osip_t *osip, char *imsi);

int sip_client_init(struct reg_proxy *reg, const char *src_ip, u_int16_t src_port,
                                           const char *dst_ip, u_int16_t dst_port);
#endif /* _SIP_H */
