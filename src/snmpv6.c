#include <errno.h>
#include <linux/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "plugin.h"
#include "utils/cmds/putval.h"
#include "utils/common/common.h"
#include "utils/ignorelist/ignorelist.h"

static const char *config_keys[] = {
    "Interface",
    "IgnoreSelected",
    "ReportInactive",
};
static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

static int interface_config(const char *key, const char *value) {
  return 0;
}

/* Copied from interface.c */
static void if_submit(const char *type, derive_t rx, derive_t tx) {
  value_list_t vl = VALUE_LIST_INIT;
  value_t values[] = {
      {.derive = rx},
      {.derive = tx},
  };

  vl.values = values;
  vl.values_len = STATIC_ARRAY_SIZE(values);
  sstrncpy(vl.plugin, "snmpv6", sizeof(vl.plugin));
  sstrncpy(vl.plugin_instance, "snmpv6", sizeof(vl.plugin_instance));
  sstrncpy(vl.type, type, sizeof(vl.type));

  plugin_dispatch_values(&vl);
} /* void if_submit */

int snmp_read(void) {
  FILE *fh;
  char buffer[1024];
  char *fields[16];
  int numfields;
  int currline = 0;
  derive_t data[76];

  if ((fh = fopen("/proc/net/snmp6", "r")) == NULL) {
    WARNING("interface plugin: fopen: %s", STRERRNO);
    return -1;
  }

  while (fgets(buffer, 1024, fh) != NULL) {
    numfields = strsplit(buffer, fields, 16);

    if (numfields < 2)
      continue;

    data[currline++] = atoll(fields[1]);
  }

  fclose(fh);

  if (currline < 25) {
    return -1;
  }

  if_submit("if_octets", data[24], data[25]);
  return 0;
}

void module_register(void) {
  plugin_register_config("snmpv6", interface_config, config_keys,
                         config_keys_num);
  plugin_register_read("snmpv6", snmp_read);
} /* void module_register */
