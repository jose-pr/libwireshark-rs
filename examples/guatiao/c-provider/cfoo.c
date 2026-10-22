/*
 * Plugins as guatiao providers, written in C: CFOO over UDP 114, a twin of
 * FOO; the `ctap` tap listener, counting frames; and the `c_double`
 * display-filter function. libwireshark-guatiao loads this library and
 * registers what it describes. It links nothing: the tables come from
 * libwireshark_api.h, the value types from guatiao.h. Its answers are
 * literal trees and buffers it owns, which record no allocator. guatiao.h
 * asks a provider to build an answer in the allocator the carrier names;
 * a Rust caller such as libwireshark-guatiao copies any answer as the call
 * returns, which is what these rely on. A provider for other hosts builds
 * through the carrier's `alloc`.
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

/* ---- the tap listener: -z ctap --------------------------------------------- */

static guatiao_entry TAP_DESCRIPTION[] = {
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("ctap")),
    GUATIAO_ENTRY_LIT("tap", GUATIAO_VALUE_STRING_LIT("frame")),
};

static guatiao_status tap_describe(void *ctx, guatiao_map *out, guatiao_provider_error *err) {
  (void)ctx;
  (void)err;
  out->ptr = TAP_DESCRIPTION;
  out->len = sizeof(TAP_DESCRIPTION) / sizeof(TAP_DESCRIPTION[0]);
  out->cap = 0;
  out->alloc = NULL;
  return GUATIAO_OK;
}

/* One invocation's count, and the report `draw` lends the host to copy. */
typedef struct {
  unsigned long long frames;
  char report[64];
} frame_count;

static void listener_destroy(void *ctx) { free(ctx); }

static guatiao_status listener_packet(void *ctx, const guatiao_map *packet,
                                      guatiao_provider_error *err) {
  (void)packet;
  (void)err;
  ((frame_count *)ctx)->frames++;
  return GUATIAO_OK;
}

static guatiao_status listener_draw(void *ctx, guatiao_string *out, guatiao_provider_error *err) {
  (void)err;
  frame_count *count = (frame_count *)ctx;
  int len = snprintf(count->report, sizeof(count->report), "ctap: %llu frames\n", count->frames);
  out->ptr = (uint8_t *)count->report;
  out->len = len > 0 ? (size_t)len : 0;
  out->cap = 0; /* not owned: the host copies it */
  out->alloc = NULL;
  return GUATIAO_OK;
}

static guatiao_status listener_reset(void *ctx, guatiao_provider_error *err) {
  (void)err;
  ((frame_count *)ctx)->frames = 0;
  return GUATIAO_OK;
}

static const wireshark_tap_listener_vtable LISTENER = {
    {(uint32_t)sizeof(wireshark_tap_listener_vtable), wireshark_tap_listener_vtable_FLOOR_HASH},
    listener_destroy,
    listener_packet,
    listener_draw,
    listener_reset,
};

/* A listener the host owns: its destroy frees the count. */
static guatiao_status tap_open(void *ctx, guatiao_object *out, guatiao_provider_error *err) {
  (void)ctx;
  (void)err;
  frame_count *count = (frame_count *)calloc(1, sizeof(frame_count));
  if (!count) {
    return GUATIAO_ERR_ALLOC;
  }
  out->table = &LISTENER;
  out->size = sizeof(LISTENER);
  out->ctx = count;
  return GUATIAO_OK;
}

static const wireshark_tap_vtable TAP = {
    {(uint32_t)sizeof(wireshark_tap_vtable), wireshark_tap_vtable_FLOOR_HASH},
    tap_describe,
    tap_open,
};

/* ---- the display-filter function: c_double(field) ------------------------- */

static guatiao_entry DOUBLE_DESCRIPTION[] = {
    GUATIAO_ENTRY_LIT("name", GUATIAO_VALUE_STRING_LIT("c_double")),
    GUATIAO_ENTRY_LIT("returns", GUATIAO_VALUE_STRING_LIT("count")),
};

static guatiao_status double_describe(void *ctx, guatiao_map *out, guatiao_provider_error *err) {
  (void)ctx;
  (void)err;
  out->ptr = DOUBLE_DESCRIPTION;
  out->len = sizeof(DOUBLE_DESCRIPTION) / sizeof(DOUBLE_DESCRIPTION[0]);
  out->cap = 0;
  out->alloc = NULL;
  return GUATIAO_OK;
}

/* The answer's digits, per thread: the host copies them as the call
 * returns. */
static _Thread_local char doubled[24];

/* Twice an integer field's value; null (no answer) for anything else. */
static guatiao_status double_call(void *ctx, const guatiao_value *value, guatiao_value *out,
                                  guatiao_provider_error *err) {
  (void)ctx;
  (void)err;
  const guatiao_value null_value = GUATIAO_VALUE_NULL_LIT;
  *out = null_value;
  if (!value || value->tag != (uint32_t)GUATIAO_NUMBER || value->payload.number.len == 0 ||
      value->payload.number.len >= sizeof(doubled)) {
    return GUATIAO_OK;
  }
  char digits[24] = {0};
  memcpy(digits, value->payload.number.ptr, value->payload.number.len);
  if (digits[0] == '-') {
    return GUATIAO_OK; /* a negative value: no answer */
  }
  unsigned long long number = strtoull(digits, NULL, 10);
  if (number > 0xFFFFFFFFull / 2) {
    return GUATIAO_OK; /* twice it is past a 32-bit count: no answer */
  }
  int len = snprintf(doubled, sizeof(doubled), "%llu", number * 2);
  out->tag = (uint32_t)GUATIAO_NUMBER;
  out->payload.number.ptr = (uint8_t *)doubled;
  out->payload.number.len = len > 0 ? (size_t)len : 0;
  out->payload.number.cap = 0;
  out->payload.number.alloc = NULL;
  return GUATIAO_OK;
}

static const wireshark_filter_function_vtable DOUBLE = {
    {(uint32_t)sizeof(wireshark_filter_function_vtable),
     wireshark_filter_function_vtable_FLOOR_HASH},
    double_describe,
    double_call,
};

/* ---- the envelope ---------------------------------------------------------- */

static const wireshark_dissector_vtable TABLE = {
    {(uint32_t)sizeof(wireshark_dissector_vtable), wireshark_dissector_vtable_FLOOR_HASH},
    describe,
    dissect_on,
    dissect,
    NULL, /* message_len: not framed over TCP */
};

#define KIND(name) {(const uint8_t *)(name), sizeof(name) - 1}

static const guatiao_str DISSECTOR_KINDS[] = {KIND("wireshark_dissector")};
static const guatiao_str TAP_KINDS[] = {KIND("wireshark_tap")};
static const guatiao_str DOUBLE_KINDS[] = {KIND("wireshark_filter_function")};

static const guatiao_kind_table DISSECTOR_TABLES[] = {{
    (uint32_t)sizeof(guatiao_kind_table),
    (uint32_t)sizeof(wireshark_dissector_vtable),
    KIND("wireshark_dissector"),
    &TABLE,
}};
static const guatiao_kind_table TAP_TABLES[] = {{
    (uint32_t)sizeof(guatiao_kind_table),
    (uint32_t)sizeof(wireshark_tap_vtable),
    KIND("wireshark_tap"),
    &TAP,
}};
static const guatiao_kind_table DOUBLE_TABLES[] = {{
    (uint32_t)sizeof(guatiao_kind_table),
    (uint32_t)sizeof(wireshark_filter_function_vtable),
    KIND("wireshark_filter_function"),
    &DOUBLE,
}};

static guatiao_provider_info PROVIDERS[3];
static guatiao_library_info LIBRARY;

/* What a scanner reads before mapping this file. */
EXPORT const char guatiao_declares[] =
    "kind=wireshark_dissector\0kind=wireshark_tap\0kind=wireshark_filter_function\0";

/* One provider of one kind, served through `tables`. */
static void provider(guatiao_provider_info *info, const char *id, const char *display_name,
                     const guatiao_str *kinds, const guatiao_kind_table *tables) {
  memset(info, 0, sizeof(*info));
  info->struct_size = (uint32_t)sizeof(guatiao_provider_info);
  info->kinds.ptr = kinds;
  info->kinds.len = 1;
  info->id = guatiao_cstr(id);
  info->display_name = guatiao_cstr(display_name);
  info->version = guatiao_cstr("0.1.0");
  info->tables.ptr = tables;
  info->tables.len = 1;
  info->tables.stride = sizeof(guatiao_kind_table);
}

EXPORT const guatiao_library_info *guatiao_library_entry(const guatiao_host_info *host) {
  if (!host || host->abi_version != GUATIAO_ABI_VERSION) {
    return NULL;
  }
  provider(&PROVIDERS[0], "cfoo", "FOO, in C", DISSECTOR_KINDS, DISSECTOR_TABLES);
  provider(&PROVIDERS[1], "ctap", "Frames, counted in C", TAP_KINDS, TAP_TABLES);
  provider(&PROVIDERS[2], "c_double", "Twice a value, in C", DOUBLE_KINDS, DOUBLE_TABLES);

  memset(&LIBRARY, 0, sizeof(LIBRARY));
  LIBRARY.struct_size = (uint32_t)sizeof(guatiao_library_info);
  LIBRARY.abi_version = GUATIAO_ABI_VERSION;
  LIBRARY.id = guatiao_cstr("cfoo");
  LIBRARY.version = guatiao_cstr("0.1.0");
  LIBRARY.providers.ptr = PROVIDERS;
  LIBRARY.providers.len = 3;
  LIBRARY.providers.stride = sizeof(guatiao_provider_info);
  return &LIBRARY;
}
