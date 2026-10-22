/*
 * A dissector as a guatiao provider, written in C: CFOO over UDP 114, a
 * twin of FOO. libwireshark-guatiao loads this library and registers the
 * protocol it describes. It links nothing: the tables come from
 * libwireshark_api.h, the value types from guatiao.h. Its description and
 * its bindings are literal trees, which record no allocator: guatiao.h's
 * rule for an answer built anywhere but the carrier's allocator is that
 * the caller copies it, and this host does before using it.
 *
 * The header is declared, not parsed: the host decodes it and adds its
 * fields, and `dissect` reads the decoded values by name.
 *
 * Build it as a shared library, with both headers' directories included:
 *   clang -shared -std=c11 -I <guatiao>/include -I <libwireshark-api>/include
 *     cfoo.c -o cfoo.dll        (add -fPIC elsewhere, and name it libcfoo.so)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guatiao.h"
#include "libwireshark_api.h"

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

/* ---- the description: a literal tree ------------------------------------ */

static guatiao_entry SEVEN[] = {
    GUATIAO_ENTRY_LIT("value", GUATIAO_VALUE_NUMBER_LIT("7")),
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("seven")),
};
static guatiao_value VERSION_VALUES[] = {GUATIAO_VALUE_MAP_LIT(SEVEN)};
static guatiao_entry VERSION[] = {
    GUATIAO_ENTRY_LIT("abbrev", GUATIAO_VALUE_STRING_LIT("version")),
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("Version")),
    GUATIAO_ENTRY_LIT("type", GUATIAO_VALUE_STRING_LIT("u8")),
    GUATIAO_ENTRY_LIT("values", GUATIAO_VALUE_LIST_LIT(VERSION_VALUES)),
};
static guatiao_entry LENGTH[] = {
    GUATIAO_ENTRY_LIT("abbrev", GUATIAO_VALUE_STRING_LIT("length")),
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("Length")),
    GUATIAO_ENTRY_LIT("type", GUATIAO_VALUE_STRING_LIT("u16")),
};
static guatiao_entry FLAGS[] = {
    GUATIAO_ENTRY_LIT("abbrev", GUATIAO_VALUE_STRING_LIT("flags")),
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("Flags")),
    GUATIAO_ENTRY_LIT("type", GUATIAO_VALUE_STRING_LIT("u8")),
    GUATIAO_ENTRY_LIT("base", GUATIAO_VALUE_STRING_LIT("hex")),
};
static guatiao_value HEADER[] = {GUATIAO_VALUE_MAP_LIT(VERSION), GUATIAO_VALUE_MAP_LIT(FLAGS),
                                 GUATIAO_VALUE_MAP_LIT(LENGTH)};
static guatiao_entry UNKNOWN_VERSION[] = {
    GUATIAO_ENTRY_LIT("abbrev", GUATIAO_VALUE_STRING_LIT("unknown_version")),
    GUATIAO_ENTRY_LIT("group", GUATIAO_VALUE_STRING_LIT("malformed")),
    GUATIAO_ENTRY_LIT("severity", GUATIAO_VALUE_STRING_LIT("warn")),
    GUATIAO_ENTRY_LIT("summary", GUATIAO_VALUE_STRING_LIT("Unknown version")),
};
static guatiao_value EXPERTS[] = {GUATIAO_VALUE_MAP_LIT(UNKNOWN_VERSION)};
static guatiao_entry DESCRIPTION[] = {
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("C FOO Protocol")),
    GUATIAO_ENTRY_LIT("short_name", GUATIAO_VALUE_STRING_LIT("CFOO")),
    GUATIAO_ENTRY_LIT("filter_name", GUATIAO_VALUE_STRING_LIT("cfoo")),
    GUATIAO_ENTRY_LIT("header", GUATIAO_VALUE_LIST_LIT(HEADER)),
    GUATIAO_ENTRY_LIT("experts", GUATIAO_VALUE_LIST_LIT(EXPERTS)),
};

/* Where CFOO gets packets: a fixed port, so no preferences. */
static guatiao_entry UDP_114[] = {
    GUATIAO_ENTRY_LIT("on", GUATIAO_VALUE_STRING_LIT("table")),
    GUATIAO_ENTRY_LIT("table", GUATIAO_VALUE_STRING_LIT("udp.port")),
    GUATIAO_ENTRY_LIT("value", GUATIAO_VALUE_NUMBER_LIT("114")),
};
static guatiao_value BINDINGS[] = {GUATIAO_VALUE_MAP_LIT(UDP_114)};

/* Answers the literal: it records no allocator, so the caller copies it. */
static guatiao_status describe(void *ctx, guatiao_map *out, guatiao_provider_error *err) {
  (void)ctx;
  (void)err;
  out->ptr = DESCRIPTION;
  out->len = sizeof(DESCRIPTION) / sizeof(DESCRIPTION[0]);
  out->cap = 0;
  out->alloc = NULL;
  return GUATIAO_OK;
}

static guatiao_status dissect_on(void *ctx, const guatiao_map *preferences, guatiao_list *out,
                                 guatiao_provider_error *err) {
  (void)ctx;
  (void)preferences;
  (void)err;
  out->ptr = BINDINGS;
  out->len = sizeof(BINDINGS) / sizeof(BINDINGS[0]);
  out->cap = 0;
  out->alloc = NULL;
  return GUATIAO_OK;
}

/* ---- dissection ---------------------------------------------------------- */

/* The decoded header field `name`, a number written as text; false when the
 * packet was too short for it. */
static bool header_number(const guatiao_map *header, const char *name, unsigned long long *out) {
  size_t len = strlen(name);
  for (size_t i = 0; header && i < header->len; i++) {
    const guatiao_entry *e = &header->ptr[i];
    if (e->key.len == len && memcmp(e->key.ptr, name, len) == 0 &&
        e->value.tag == (uint32_t)GUATIAO_NUMBER) {
      char digits[24] = {0};
      size_t n = e->value.payload.text.len < sizeof(digits) - 1 ? e->value.payload.text.len
                                                                : sizeof(digits) - 1;
      memcpy(digits, e->value.payload.text.ptr, n);
      *out = strtoull(digits, NULL, 10);
      return true;
    }
  }
  return false;
}

/* A refusal's message is the callee's to give and the caller's to free. */
static void forget(guatiao_provider_error *err) {
  if (err->message.cap && err->message.alloc) {
    err->message.alloc->free(err->message.alloc->ctx, err->message.ptr, err->message.cap, 1);
  }
  memset(err, 0, sizeof(*err));
}

static guatiao_status dissect(void *ctx, guatiao_bytes data, const guatiao_map *header,
                              const guatiao_map *preferences, const guatiao_object *packet,
                              guatiao_map *conversation, int64_t *out,
                              guatiao_provider_error *err) {
  (void)ctx;
  (void)preferences;
  (void)conversation;
  (void)err;
  *out = 0;
  unsigned long long version = 0;
  if (!header_number(header, "length", &version) || !header_number(header, "version", &version) ||
      !packet || packet->size < sizeof(wireshark_packet_vtable)) {
    return GUATIAO_OK; /* shorter than the header: not CFOO */
  }
  const wireshark_packet_vtable *p = (const wireshark_packet_vtable *)packet->table;
  if (version != 7) {
    guatiao_provider_error refused;
    memset(&refused, 0, sizeof(refused));
    p->add_expert(packet->ctx, guatiao_cstr("unknown_version"), guatiao_cstr(""), &refused);
    forget(&refused);
  }

  int64_t frame = 0;
  p->frame_number(packet->ctx, &frame);
  char info[64];
  int len = snprintf(info, sizeof(info), "CFOO version %llu, frame %lld", version,
                     (long long)frame);
  guatiao_str text = {(const uint8_t *)info, len > 0 ? (size_t)len : 0};
  p->set_info(packet->ctx, text);
  *out = (int64_t)data.len;
  return GUATIAO_OK;
}

/* ---- the envelope ---------------------------------------------------------- */

static const wireshark_dissector_vtable TABLE = {
    {(uint32_t)sizeof(wireshark_dissector_vtable), wireshark_dissector_vtable_FLOOR_HASH},
    describe,
    dissect_on,
    dissect,
    NULL, /* message_len: not framed over TCP */
};

static const guatiao_str KINDS[] = {{(const uint8_t *)"wireshark_dissector", 19}};

static const guatiao_kind_table TABLES[] = {{
    (uint32_t)sizeof(guatiao_kind_table),
    (uint32_t)sizeof(wireshark_dissector_vtable),
    {(const uint8_t *)"wireshark_dissector", 19},
    &TABLE,
}};

static guatiao_provider_info PROVIDER;
static guatiao_library_info LIBRARY;

/* What a scanner reads before mapping this file. */
EXPORT const char guatiao_declares[] = "kind=wireshark_dissector\0";

EXPORT const guatiao_library_info *guatiao_library_entry(const guatiao_host_info *host) {
  if (!host || host->abi_version != GUATIAO_ABI_VERSION) {
    return NULL;
  }
  memset(&PROVIDER, 0, sizeof(PROVIDER));
  PROVIDER.struct_size = (uint32_t)sizeof(guatiao_provider_info);
  PROVIDER.kinds.ptr = KINDS;
  PROVIDER.kinds.len = 1;
  PROVIDER.id = guatiao_cstr("cfoo");
  PROVIDER.display_name = guatiao_cstr("FOO, in C");
  PROVIDER.version = guatiao_cstr("0.1.0");
  PROVIDER.tables.ptr = TABLES;
  PROVIDER.tables.len = 1;
  PROVIDER.tables.stride = sizeof(guatiao_kind_table);

  memset(&LIBRARY, 0, sizeof(LIBRARY));
  LIBRARY.struct_size = (uint32_t)sizeof(guatiao_library_info);
  LIBRARY.abi_version = GUATIAO_ABI_VERSION;
  LIBRARY.id = guatiao_cstr("cfoo");
  LIBRARY.version = guatiao_cstr("0.1.0");
  LIBRARY.providers.ptr = &PROVIDER;
  LIBRARY.providers.len = 1;
  LIBRARY.providers.stride = sizeof(guatiao_provider_info);
  return &LIBRARY;
}
