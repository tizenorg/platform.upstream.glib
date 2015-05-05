/*  GIO - GLib Input, Output and Streaming Library
 *
 * Copyright (C) 2013 Samsung Electronics
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Michal Eljasiewicz   <m.eljasiewic@samsung.com>
 * Author: Lukasz Skalski       <l.skalski@samsung.com>
 */

#include "config.h"
#include "gkdbus.h"
#include "glib-unix.h"
#include "glibintl.h"
#include "kdbus.h"

#include <gio/gio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdint.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <glib/gstdio.h>
#include <glib/glib-private.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#include "glibintl.h"
#include "gunixfdmessage.h"

#define KDBUS_MSG_MAX_SIZE         8192
#define KDBUS_TIMEOUT_NS           2000000000LU
#define KDBUS_POOL_SIZE            (16 * 1024LU * 1024LU)
#define KDBUS_ALIGN8(l)            (((l) + 7) & ~7)
#define KDBUS_ALIGN8_PTR(p)        ((void*) (uintptr_t)(p))

#define KDBUS_ITEM_HEADER_SIZE G_STRUCT_OFFSET(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)

#define KDBUS_ITEM_NEXT(item) \
        (typeof(item))(((guint8 *)item) + KDBUS_ALIGN8((item)->size))
#define KDBUS_ITEM_FOREACH(item, head, first)                    \
        for (item = (head)->first;                               \
             (guint8 *)(item) < (guint8 *)(head) + (head)->size; \
             item = KDBUS_ITEM_NEXT(item))
#define KDBUS_FOREACH(iter, first, _size)                             \
        for (iter = (first);                                          \
             ((guint8 *)(iter) < (guint8 *)(first) + (_size)) &&      \
               ((guint8 *)(iter) >= (guint8 *)(first));               \
             iter = (void*)(((guint8 *)iter) + KDBUS_ALIGN8((iter)->size)))

#define g_alloca0(x) memset(g_alloca(x), '\0', (x))

struct dbus_fixed_header {
  guint8  endian;
  guint8  type;
  guint8  flags;
  guint8  version;
  guint32 reserved;
  guint64 serial;
};

#define DBUS_FIXED_HEADER_TYPE     ((const GVariantType *) "(yyyyut)")
#define DBUS_EXTENDED_HEADER_TYPE  ((const GVariantType *) "a{tv}")
#define DBUS_MESSAGE_TYPE          ((const GVariantType *) "((yyyyut)a{tv}v)")

/*
 * Macros for SipHash algorithm
 */

#define ROTL(x,b) (guint64)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)         \
    (p)[0] = (guint8)((v)      ); (p)[1] = (guint8)((v) >>  8); \
    (p)[2] = (guint8)((v) >> 16); (p)[3] = (guint8)((v) >> 24);

#define U64TO8_LE(p, v)         \
  U32TO8_LE((p),     (guint32)((v)      ));   \
  U32TO8_LE((p) + 4, (guint32)((v) >> 32));

#define U8TO64_LE(p) \
  (((guint64)((p)[0])      ) | \
   ((guint64)((p)[1]) <<  8) | \
   ((guint64)((p)[2]) << 16) | \
   ((guint64)((p)[3]) << 24) | \
   ((guint64)((p)[4]) << 32) | \
   ((guint64)((p)[5]) << 40) | \
   ((guint64)((p)[6]) << 48) | \
   ((guint64)((p)[7]) << 56))

#define SIPROUND            \
  do {              \
    v0 += v1; v1=ROTL(v1,13); v1 ^= v0; v0=ROTL(v0,32); \
    v2 += v3; v3=ROTL(v3,16); v3 ^= v2;     \
    v0 += v3; v3=ROTL(v3,21); v3 ^= v0;     \
    v2 += v1; v1=ROTL(v1,17); v1 ^= v2; v2=ROTL(v2,32); \
  } while(0)

typedef enum
{
  G_BUS_CREDS_PID              = 1,
  G_BUS_CREDS_UID              = 2,
  G_BUS_CREDS_UNIQUE_NAME      = 3,
  G_BUS_CREDS_SELINUX_CONTEXT  = 4
} GBusCredentialsFlags;

typedef GObjectClass GKDBusWorkerClass;

struct _GKDBusWorker
{
  GObject            parent_instance;

  gint               fd;

  GMainContext      *context;
  GSource           *source;

  gchar             *kdbus_buffer;

  gchar             *unique_name;
  guint64            unique_id;

  guint64            flags;
  guint64            attach_flags_send;
  guint64            attach_flags_recv;

  gsize              bloom_size;
  guint              bloom_n_hash;

  guint              closed : 1;
  guint              inited : 1;
  guint              timeout;
  guint              timed_out : 1;

  guchar             bus_id[16];

  GDBusCapabilityFlags                     capabilities;
  GDBusWorkerMessageReceivedCallback       message_received_callback;
  GDBusWorkerMessageAboutToBeSentCallback  message_about_to_be_sent_callback;
  GDBusWorkerDisconnectedCallback          disconnected_callback;
  gpointer                                 user_data;
};

static gssize _g_kdbus_receive (GKDBusWorker  *kdbus,
                                GCancellable  *cancellable,
                                GError       **error);

G_DEFINE_TYPE (GKDBusWorker, g_kdbus_worker, G_TYPE_OBJECT)

/* Hash keys for bloom filters*/
const guint8 hash_keys[8][16] =
{
  {0xb9,0x66,0x0b,0xf0,0x46,0x70,0x47,0xc1,0x88,0x75,0xc4,0x9c,0x54,0xb9,0xbd,0x15},
  {0xaa,0xa1,0x54,0xa2,0xe0,0x71,0x4b,0x39,0xbf,0xe1,0xdd,0x2e,0x9f,0xc5,0x4a,0x3b},
  {0x63,0xfd,0xae,0xbe,0xcd,0x82,0x48,0x12,0xa1,0x6e,0x41,0x26,0xcb,0xfa,0xa0,0xc8},
  {0x23,0xbe,0x45,0x29,0x32,0xd2,0x46,0x2d,0x82,0x03,0x52,0x28,0xfe,0x37,0x17,0xf5},
  {0x56,0x3b,0xbf,0xee,0x5a,0x4f,0x43,0x39,0xaf,0xaa,0x94,0x08,0xdf,0xf0,0xfc,0x10},
  {0x31,0x80,0xc8,0x73,0xc7,0xea,0x46,0xd3,0xaa,0x25,0x75,0x0f,0x9e,0x4c,0x09,0x29},
  {0x7d,0xf7,0x18,0x4b,0x7b,0xa4,0x44,0xd5,0x85,0x3c,0x06,0xe0,0x65,0x53,0x96,0x6d},
  {0xf2,0x77,0xe9,0x6f,0x93,0xb5,0x4e,0x71,0x9a,0x0c,0x34,0x88,0x39,0x25,0xbf,0x35}
};

enum {
  MATCH_ELEMENT_TYPE,
  MATCH_ELEMENT_SENDER,
  MATCH_ELEMENT_INTERFACE,
  MATCH_ELEMENT_MEMBER,
  MATCH_ELEMENT_PATH,
  MATCH_ELEMENT_PATH_NAMESPACE,
  MATCH_ELEMENT_DESTINATION,
  MATCH_ELEMENT_ARG0NAMESPACE,
  MATCH_ELEMENT_EAVESDROP,
  MATCH_ELEMENT_ARGN,
  MATCH_ELEMENT_ARGNPATH,
};

/* MatchElement struct */
typedef struct {
  guint16 type;
  guint16 arg;
  char *value;
} MatchElement;

/* Match struct */
typedef struct {
  int n_elements;
  MatchElement *elements;
} Match;


/**
 * SipHash algorithm
 *
 */
static void
_g_siphash24 (guint8         out[8],
              const void    *_in,
              gsize          inlen,
              const guint8   k[16])
{
  /* "somepseudorandomlygeneratedbytes" */
  guint64 v0 = 0x736f6d6570736575ULL;
  guint64 v1 = 0x646f72616e646f6dULL;
  guint64 v2 = 0x6c7967656e657261ULL;
  guint64 v3 = 0x7465646279746573ULL;
  guint64 b;
  guint64 k0 = U8TO64_LE (k);
  guint64 k1 = U8TO64_LE (k + 8);
  guint64 m;
  const guint8 *in = _in;
  const guint8 *end = in + inlen - (inlen % sizeof(guint64));
  const int left = inlen & 7;
  b = ((guint64) inlen) << 56;
  v3 ^= k1;
  v2 ^= k0;
  v1 ^= k1;
  v0 ^= k0;

  for (; in != end; in += 8)
    {
      m = U8TO64_LE (in);
      v3 ^= m;
      SIPROUND;
      SIPROUND;
      v0 ^= m;
    }

  switch (left)
    {
      case 7: b |= ((guint64) in[6]) << 48;
      case 6: b |= ((guint64) in[5]) << 40;
      case 5: b |= ((guint64) in[4]) << 32;
      case 4: b |= ((guint64) in[3]) << 24;
      case 3: b |= ((guint64) in[2]) << 16;
      case 2: b |= ((guint64) in[1]) <<  8;
      case 1: b |= ((guint64) in[0]); break;
      case 0: break;
    }

  v3 ^= b;
  SIPROUND;
  SIPROUND;
  v0 ^= b;

  v2 ^= 0xff;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  SIPROUND;
  b = v0 ^ v1 ^ v2  ^ v3;
  U64TO8_LE (out, b);
}


/**
 * is_key()
 *
 */
static gboolean
is_key (const char *key_start, const char *key_end, char *value)
{
  gsize len = strlen (value);

  if (len != key_end - key_start)
    return FALSE;

  return strncmp (key_start, value, len) == 0;
}


/**
 * parse_key()
 *
 */
static gboolean
parse_key (MatchElement *element, const char *key_start, const char *key_end)
{
  gboolean res = TRUE;

  if (is_key (key_start, key_end, "type"))
    {
      element->type = MATCH_ELEMENT_TYPE;
    }
  else if (is_key (key_start, key_end, "sender"))
    {
      element->type = MATCH_ELEMENT_SENDER;
    }
  else if (is_key (key_start, key_end, "interface"))
    {
      element->type = MATCH_ELEMENT_INTERFACE;
    }
  else if (is_key (key_start, key_end, "member"))
    {
      element->type = MATCH_ELEMENT_MEMBER;
    }
  else if (is_key (key_start, key_end, "path"))
    {
      element->type = MATCH_ELEMENT_PATH;
    }
  else if (is_key (key_start, key_end, "path_namespace"))
    {
      element->type = MATCH_ELEMENT_PATH_NAMESPACE;
    }
  else if (is_key (key_start, key_end, "destination"))
    {
      element->type = MATCH_ELEMENT_DESTINATION;
    }
  else if (is_key (key_start, key_end, "arg0namespace"))
    {
      element->type = MATCH_ELEMENT_ARG0NAMESPACE;
    }
  else if (is_key (key_start, key_end, "eavesdrop"))
    {
      element->type = MATCH_ELEMENT_EAVESDROP;
    }
  else if (key_end - key_start > 3 && is_key (key_start, key_start + 3, "arg"))
    {
      const char *digits = key_start + 3;
      const char *end_digits = digits;

      while (end_digits < key_end && g_ascii_isdigit (*end_digits))
        end_digits++;

      if (end_digits == key_end) /* argN */
        {
          element->type = MATCH_ELEMENT_ARGN;
          element->arg = atoi (digits);
        }
      else if (is_key (end_digits, key_end, "path")) /* argNpath */
        {
          element->type = MATCH_ELEMENT_ARGNPATH;
          element->arg = atoi (digits);
        }
      else
        res = FALSE;
    }
  else
    res = FALSE;

  return res;
}


/**
 * parse_value()
 *
 */
static const char *
parse_value (MatchElement *element, const char *s)
{
  char quote_char;
  GString *value;

  value = g_string_new ("");

  quote_char = 0;

  for (;*s; s++)
    {
      if (quote_char == 0)
        {
          switch (*s)
            {
            case '\'':
              quote_char = '\'';
              break;

            case ',':
              s++;
              goto out;

            case '\\':
              quote_char = '\\';
              break;

            default:
              g_string_append_c (value, *s);
              break;
            }
        }
      else if (quote_char == '\\')
        {
          /* \ only counts as an escape if escaping a quote mark */
          if (*s != '\'')
            g_string_append_c (value, '\\');

          g_string_append_c (value, *s);
          quote_char = 0;
        }
      else /* quote_char == ' */
        {
          if (*s == '\'')
            quote_char = 0;
          else
            g_string_append_c (value, *s);
        }
    }

 out:
  if (quote_char == '\\')
    g_string_append_c (value, '\\');
  else if (quote_char == '\'')
    {
      g_string_free (value, TRUE);
      return NULL;
    }

  element->value = g_string_free (value, FALSE);
  return s;
}


/**
 * match_new()
 *
 */
static Match *
match_new (const char *str)
{
  Match *match;
  GArray *elements;
  const char *p;
  const char *key_start;
  const char *key_end;
  MatchElement element;
  int i;

  elements = g_array_new (TRUE, TRUE, sizeof (MatchElement));

  p = str;

  while (*p != 0)
    {
      memset (&element, 0, sizeof (element));

      /* Skip initial whitespace */
      while (*p && g_ascii_isspace (*p))
        p++;

      key_start = p;

      /* Read non-whitespace non-equals chars */
      while (*p && *p != '=' && !g_ascii_isspace (*p))
        p++;

      key_end = p;

      /* Skip any whitespace after key */
      while (*p && g_ascii_isspace (*p))
        p++;

      if (key_start == key_end)
        continue; /* Allow trailing whitespace */
      if (*p != '=')
        goto error;

      ++p;

      if (!parse_key (&element, key_start, key_end))
        goto error;

      p = parse_value (&element, p);
      if (p == NULL)
        goto error;

      g_array_append_val (elements, element);
    }

  match = g_new0 (Match, 1);
  match->n_elements = elements->len;
  match->elements = (MatchElement *)g_array_free (elements, FALSE);

  return match;

 error:
  for (i = 0; i < elements->len; i++)
    g_free (g_array_index (elements, MatchElement, i).value);
  g_array_free (elements, TRUE);
  return NULL;
}


/**
 * match_free()
 *
 */
static void
match_free (Match *match)
{
  int i;
  for (i = 0; i < match->n_elements; i++)
    g_free (match->elements[i].value);
  g_free (match->elements);
  g_free (match);
}


/**
 * g_kdbus_finalize:
 *
 */
static void
g_kdbus_worker_finalize (GObject *object)
{
  GKDBusWorker *kdbus = G_KDBUS_WORKER (object);

  if (kdbus->kdbus_buffer != NULL)
    munmap (kdbus->kdbus_buffer, KDBUS_POOL_SIZE);

  kdbus->kdbus_buffer = NULL;

  if (kdbus->fd != -1 && !kdbus->closed)
    _g_kdbus_close (kdbus);

  G_OBJECT_CLASS (g_kdbus_worker_parent_class)->finalize (object);
}

static void
g_kdbus_worker_class_init (GKDBusWorkerClass *class)
{
  class->finalize = g_kdbus_worker_finalize;
}

static void
g_kdbus_worker_init (GKDBusWorker *kdbus)
{
  kdbus->fd = -1;

  kdbus->unique_id = -1;
  kdbus->unique_name = NULL;

  kdbus->kdbus_buffer = NULL;

  kdbus->flags = KDBUS_HELLO_ACCEPT_FD;
  kdbus->attach_flags_send = _KDBUS_ATTACH_ALL;
  kdbus->attach_flags_recv = _KDBUS_ATTACH_ALL;
}

static gboolean
kdbus_ready (gint         fd,
             GIOCondition condition,
             gpointer     user_data)
{
  GKDBusWorker *kdbus = user_data;
  GError *error = NULL;

  _g_kdbus_receive (kdbus, NULL, &error);
  g_assert_no_error (error);

  return G_SOURCE_CONTINUE;
}

gboolean
_g_kdbus_open (GKDBusWorker  *worker,
               const gchar   *address,
               GError       **error)
{
  g_return_val_if_fail (G_IS_KDBUS_WORKER (worker), FALSE);

  worker->fd = open(address, O_RDWR|O_NOCTTY|O_CLOEXEC);
  if (worker->fd<0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, _("Can't open kdbus endpoint"));
      return FALSE;
    }

  worker->closed = FALSE;

  return TRUE;
}


/**
 * g_kdbus_free_data:
 *
 */
static gboolean
g_kdbus_free_data (GKDBusWorker      *kdbus,
                   guint64      offset)
{
  struct kdbus_cmd_free cmd = {
    .size = sizeof(cmd),
    .offset = offset,
    .flags = 0
  };
  int ret;

  ret = ioctl (kdbus->fd, KDBUS_CMD_FREE, &cmd);
  if (ret < 0)
    return FALSE;

  return TRUE;
}


/**
 * g_kdbus_translate_nameowner_flags:
 *
 */
static void
g_kdbus_translate_nameowner_flags (GBusNameOwnerFlags   flags,
                                   guint64             *kdbus_flags)
{
  guint64 new_flags;

  new_flags = 0;

  if (flags & G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT)
    new_flags |= KDBUS_NAME_ALLOW_REPLACEMENT;

  if (flags & G_BUS_NAME_OWNER_FLAGS_REPLACE)
    new_flags |= KDBUS_NAME_REPLACE_EXISTING;

  if (!(flags & G_BUS_NAME_OWNER_FLAGS_DO_NOT_QUEUE))
    new_flags |= KDBUS_NAME_QUEUE;

  *kdbus_flags = new_flags;
}


/**
 * _g_kdbus_close:
 *
 */
void
_g_kdbus_close (GKDBusWorker *kdbus)
{
  g_return_val_if_fail (G_IS_KDBUS_WORKER (kdbus), FALSE);

  if (kdbus->closed)
    return;

  g_source_destroy (kdbus->source);
  kdbus->source = 0;

  g_main_context_unref (kdbus->context);
  kdbus->context = NULL;

  close (kdbus->fd);
  kdbus->fd = -1;

  kdbus->closed = TRUE;
}

/**
 * _g_kdbus_is_closed:
 *
 */
gboolean
_g_kdbus_is_closed (GKDBusWorker  *kdbus)
{
  g_return_val_if_fail (G_IS_KDBUS_WORKER (kdbus), FALSE);

  return kdbus->closed;
}


/**
 * _g_kdbus_Hello:
 *
 */
GVariant *
_g_kdbus_Hello (GKDBusWorker *worker,
                GError    **error)
{
  struct kdbus_cmd_hello *cmd;
  struct kdbus_bloom_parameter *bloom;
  struct kdbus_item *item, *items;

  gchar *conn_name;
  size_t size, conn_name_size;

  conn_name = "gdbus-kdbus";
  conn_name_size = strlen (conn_name);

  size = KDBUS_ALIGN8 (G_STRUCT_OFFSET (struct kdbus_cmd_hello, items)) +
         KDBUS_ALIGN8 (G_STRUCT_OFFSET (struct kdbus_item, str) + conn_name_size + 1);

  cmd = g_alloca0 (size);
  cmd->flags = worker->flags;
  cmd->attach_flags_send = worker->attach_flags_send;
  cmd->attach_flags_recv = worker->attach_flags_recv;
  cmd->size = size;
  cmd->pool_size = KDBUS_POOL_SIZE;

  item = cmd->items;
  item->size = G_STRUCT_OFFSET (struct kdbus_item, str) + conn_name_size + 1;
  item->type = KDBUS_ITEM_CONN_DESCRIPTION;
  memcpy (item->str, conn_name, conn_name_size+1);
  item = KDBUS_ITEM_NEXT (item);

  if (ioctl(worker->fd, KDBUS_CMD_HELLO, cmd))
    {
      g_set_error (error, G_IO_ERROR,
                   g_io_error_from_errno (errno),
                   _("Failed to send HELLO: %s"),
                   g_strerror (errno));
      return NULL;
    }

  worker->kdbus_buffer = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, worker->fd, 0);
  if (worker->kdbus_buffer == MAP_FAILED)
    {
      g_set_error (error, G_IO_ERROR,
                   g_io_error_from_errno (errno),
                   _("mmap error: %s"),
                   g_strerror (errno));
      return NULL;
    }

  if (cmd->bus_flags > 0xFFFFFFFFULL)
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_FAILED,
                           _("Incompatible HELLO flags"));
      return NULL;
    }

  memcpy (worker->bus_id, cmd->id128, 16);

  worker->unique_id = cmd->id;
  asprintf(&worker->unique_name, ":1.%llu", (unsigned long long) cmd->id);

  /* read bloom filters parameters */
  bloom = NULL;
  items = (void*)(worker->kdbus_buffer + cmd->offset);
  KDBUS_FOREACH(item, items, cmd->items_size)
    {
      switch (item->type)
        {
          case KDBUS_ITEM_BLOOM_PARAMETER:
            bloom = &item->bloom_parameter;
          break;
        }
    }

  if (bloom != NULL)
    {
      worker->bloom_size = (gsize) bloom->size;
      worker->bloom_n_hash = (guint) bloom->n_hash;
    }
  else
    {
      g_set_error_literal (error,
                           G_IO_ERROR,
                           G_IO_ERROR_FAILED,
                           _("Can't read bloom filter parameters"));
      return NULL;
    }


  return g_variant_new ("(s)", worker->unique_name);
}


/**
 * _g_kdbus_RequestName:
 *
 */
GVariant *
_g_kdbus_RequestName (GKDBusWorker        *worker,
                      const gchar         *name,
                      GBusNameOwnerFlags   flags,
                      GError             **error)
{
  GVariant *result;
  struct kdbus_cmd *cmd;
  guint64 kdbus_flags;
  gssize len, size;
  gint status, ret;

  status = G_BUS_REQUEST_NAME_FLAGS_PRIMARY_OWNER;

  if (!g_dbus_is_name (name))
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_INVALID_ARGS,
                   "Given bus name \"%s\" is not valid", name);
      return NULL;
    }

  if (*name == ':')
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_INVALID_ARGS,
                   "Cannot acquire a service starting with ':' such as \"%s\"", name);
      return NULL;
    }

  g_kdbus_translate_nameowner_flags (flags, &kdbus_flags);

  len = strlen(name) + 1;
  size = G_STRUCT_OFFSET (struct kdbus_cmd, items) + KDBUS_ITEM_SIZE(len);
  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->items[0].size = KDBUS_ITEM_HEADER_SIZE + len;
  cmd->items[0].type = KDBUS_ITEM_NAME;
  cmd->flags = kdbus_flags;
  memcpy (cmd->items[0].str, name, len);

  ret = ioctl(worker->fd, KDBUS_CMD_NAME_ACQUIRE, cmd);
  if (ret < 0)
    {
      if (errno == EEXIST)
        status = G_BUS_REQUEST_NAME_FLAGS_EXISTS;
      else if (errno == EALREADY)
        status = G_BUS_REQUEST_NAME_FLAGS_ALREADY_OWNER;
      else
        {
          g_set_error (error, G_IO_ERROR,
                       g_io_error_from_errno (errno),
                       _("Error while acquiring name: %s"),
                       g_strerror (errno));
          return NULL;
        }
    }

  if (cmd->return_flags & KDBUS_NAME_IN_QUEUE)
    status = G_BUS_REQUEST_NAME_FLAGS_IN_QUEUE;

  result = g_variant_new ("(u)", status);

  return result;
}


/**
 * _g_kdbus_ReleaseName:
 *
 */
GVariant *
_g_kdbus_ReleaseName (GKDBusWorker     *worker,
                      const gchar         *name,
                      GError             **error)
{
  GVariant *result;
  struct kdbus_cmd *cmd;
  gssize len, size;
  gint status, ret;

  status = G_BUS_RELEASE_NAME_FLAGS_RELEASED;

  if (!g_dbus_is_name (name))
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_INVALID_ARGS,
                   "Given bus name \"%s\" is not valid", name);
      return NULL;
    }

  if (*name == ':')
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_INVALID_ARGS,
                   "Cannot release a service starting with ':' such as \"%s\"", name);
      return NULL;
    }

  len = strlen(name) + 1;
  size = G_STRUCT_OFFSET (struct kdbus_cmd, items) + KDBUS_ITEM_SIZE(len);
  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->items[0].size = KDBUS_ITEM_HEADER_SIZE + len;
  cmd->items[0].type = KDBUS_ITEM_NAME;
  memcpy (cmd->items[0].str, name, len);

  ret = ioctl(worker->fd, KDBUS_CMD_NAME_RELEASE, cmd);
  if (ret < 0)
    {
      if (errno == ESRCH)
        status = G_BUS_RELEASE_NAME_FLAGS_NON_EXISTENT;
      else if (errno == EADDRINUSE)
        status = G_BUS_RELEASE_NAME_FLAGS_NOT_OWNER;
      else
        {
          g_set_error (error, G_IO_ERROR,
                       g_io_error_from_errno (errno),
                       _("Error while releasing name: %s"),
                       g_strerror (errno));
          return NULL;
        }
    }

  result = g_variant_new ("(u)", status);

  return result;
}


/**
 * _g_kdbus_GetBusId:
 *
 */
GVariant *
_g_kdbus_GetBusId (GKDBusWorker  *worker,
                   GError          **error)
{
  GVariant *result;
  GString  *result_str;
  guint     cnt;

  result_str = g_string_new (NULL);

  for (cnt=0; cnt<16; cnt++)
    g_string_append_printf (result_str, "%02x", worker->bus_id[cnt]);

  result = g_variant_new ("(s)", result_str->str);
  g_string_free (result_str, TRUE);

  return result;
}


/**
 * _g_kdbus_GetListNames:
 *
 */
GVariant *
_g_kdbus_GetListNames (GKDBusWorker  *worker,
                       guint             list_name_type,
                       GError          **error)
{
  GVariant *result;
  GVariantBuilder *builder;
  struct kdbus_info *name_list, *name;
  struct kdbus_cmd_list cmd = {
    .size = sizeof(cmd)
  };

  guint64 prev_id;
  gint ret;

  prev_id = 0;

  if (list_name_type)
    cmd.flags = KDBUS_LIST_ACTIVATORS;                /* ListActivatableNames */
  else
    cmd.flags = KDBUS_LIST_UNIQUE | KDBUS_LIST_NAMES; /* ListNames */

  ret = ioctl(worker->fd, KDBUS_CMD_LIST, &cmd);
  if (ret < 0)
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_FAILED,
                   _("Error listing names"));
      return NULL;
    }

  name_list = (struct kdbus_info *) ((guint8 *) worker->kdbus_buffer + cmd.offset);
  builder = g_variant_builder_new (G_VARIANT_TYPE ("as"));

  KDBUS_FOREACH(name, name_list, cmd.list_size)
    {
      struct kdbus_item *item;
      const gchar *item_name = "";

      if ((cmd.flags & KDBUS_LIST_UNIQUE) && name->id != prev_id)
        {
          GString *unique_name;

          unique_name = g_string_new (NULL);
          g_string_printf (unique_name, ":1.%llu", name->id);
          g_variant_builder_add (builder, "s", unique_name->str);
          g_string_free (unique_name,TRUE);
          prev_id = name->id;
        }

       KDBUS_ITEM_FOREACH(item, name, items)
         if (item->type == KDBUS_ITEM_OWNED_NAME)
           item_name = item->name.name;

        if (g_dbus_is_name (item_name))
          g_variant_builder_add (builder, "s", item_name);
    }

  result = g_variant_new ("(as)", builder);
  g_variant_builder_unref (builder);

  g_kdbus_free_data (worker, cmd.offset);
  return result;
}


/**
 * _g_kdbus_NameHasOwner_internal:
 *
 */
static gboolean
g_kdbus_NameHasOwner_internal (GKDBusWorker       *worker,
                               const gchar  *name,
                               GError      **error)
{
  struct kdbus_cmd_info *cmd;
  gssize size, len;
  gint ret;

  if (g_dbus_is_unique_name(name))
    {
       size = G_STRUCT_OFFSET (struct kdbus_cmd_info, items);
       cmd = g_alloca0 (size);
       cmd->id = g_ascii_strtoull (name+3, NULL, 10);
    }
  else
    {
       len = strlen(name) + 1;
       size = G_STRUCT_OFFSET (struct kdbus_cmd_info, items) + KDBUS_ITEM_SIZE(len);
       cmd = g_alloca0 (size);
       cmd->items[0].size = KDBUS_ITEM_HEADER_SIZE + len;
       cmd->items[0].type = KDBUS_ITEM_NAME;
       memcpy (cmd->items[0].str, name, len);
    }
  cmd->size = size;

  ret = ioctl(worker->fd, KDBUS_CMD_CONN_INFO, cmd);
  g_kdbus_free_data (worker, cmd->offset);

  if (ret < 0)
    return FALSE;
  else
    return TRUE;
}


/**
 * _g_kdbus_GetListQueuedOwners:
 *
 */
GVariant *
_g_kdbus_GetListQueuedOwners (GKDBusWorker  *worker,
                              const gchar   *name,
                              GError       **error)
{
  GVariant *result;
  GVariantBuilder *builder;
  GString *unique_name;
  gint ret;

  struct kdbus_info *name_list, *kname;
  struct kdbus_cmd_list cmd = {
    .size = sizeof(cmd),
    .flags = KDBUS_LIST_QUEUED
  };

  if (!g_dbus_is_name (name))
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_INVALID_ARGS,
                   "Given bus name \"%s\" is not valid", name);
      return NULL;
    }

  if (!g_kdbus_NameHasOwner_internal (worker, name, error))
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_NAME_HAS_NO_OWNER,
                   "Could not get owner of name '%s': no such name", name);
      return NULL;
    }

  ret = ioctl(worker->fd, KDBUS_CMD_LIST, &cmd);
  if (ret < 0)
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_FAILED,
                   _("Error listing names"));
      return NULL;
    }

  name_list = (struct kdbus_info *) ((guint8 *) worker->kdbus_buffer + cmd.offset);

  unique_name = g_string_new (NULL);
  builder = g_variant_builder_new (G_VARIANT_TYPE ("as"));
  KDBUS_FOREACH(kname, name_list, cmd.list_size)
    {
      struct kdbus_item *item;
      const char *item_name = "";

      KDBUS_ITEM_FOREACH(item, kname, items)
        if (item->type == KDBUS_ITEM_NAME)
          item_name = item->str;

      if (strcmp(item_name, name))
        continue;

      g_string_printf (unique_name, ":1.%llu", kname->id);
      g_variant_builder_add (builder, "s", item_name);
    }

  result = g_variant_new ("(as)", builder);
  g_variant_builder_unref (builder);
  g_string_free (unique_name,TRUE);

  g_kdbus_free_data (worker, cmd.offset);
  return result;
}


/**
 * g_kdbus_GetConnInfo_internal:
 *
 */
static GVariant *
g_kdbus_GetConnInfo_internal (GKDBusWorker  *worker,
                              const gchar      *name,
                              guint64           flag,
                              GError          **error)
{
  GVariant *result;

  struct kdbus_cmd_info *cmd;
  struct kdbus_info *conn_info;
  struct kdbus_item *item;
  gssize size, len;
  gint ret;

  result = NULL;

  if (!g_dbus_is_name (name))
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_INVALID_ARGS,
                   "Given bus name \"%s\" is not valid", name);
      return NULL;
    }

  if (!g_kdbus_NameHasOwner_internal (worker, name, error))
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_NAME_HAS_NO_OWNER,
                   "Could not get owner of name '%s': no such name", name);
      return NULL;
    }

  if (g_dbus_is_unique_name(name))
    {
       size = G_STRUCT_OFFSET (struct kdbus_cmd_info, items);
       cmd = g_alloca0 (size);
       cmd->id = g_ascii_strtoull (name+3, NULL, 10);
    }
  else
    {
       len = strlen(name) + 1;
       size = G_STRUCT_OFFSET (struct kdbus_cmd_info, items) + KDBUS_ITEM_SIZE(len);
       cmd = g_alloca0 (size);
       cmd->items[0].size = KDBUS_ITEM_HEADER_SIZE + len;
       cmd->items[0].type = KDBUS_ITEM_NAME;
       memcpy (cmd->items[0].str, name, len);
    }

  cmd->attach_flags = _KDBUS_ATTACH_ALL;
  cmd->size = size;

  ret = ioctl(worker->fd, KDBUS_CMD_CONN_INFO, cmd);
  if (ret < 0)
    {
      g_set_error (error,
                   G_DBUS_ERROR,
                   G_DBUS_ERROR_FAILED,
                   _("Could not get connection info"));
      return NULL;
    }

  conn_info = (struct kdbus_info *) ((guint8 *) worker->kdbus_buffer + cmd->offset);

  /*
  if (conn_info->flags & KDBUS_HELLO_ACTIVATOR)
    {}
  */

  if (flag == G_BUS_CREDS_UNIQUE_NAME)
    {
       GString *unique_name;

       unique_name = g_string_new (NULL);
       g_string_printf (unique_name, ":1.%llu", (unsigned long long) conn_info->id);
       result = g_variant_new ("(s)", unique_name->str);
       g_string_free (unique_name,TRUE);
       goto exit;
    }

  KDBUS_ITEM_FOREACH(item, conn_info, items)
   {
      switch (item->type)
        {
          case KDBUS_ITEM_PIDS:

            if (flag == G_BUS_CREDS_PID)
              {
                guint pid = item->pids.pid;
                result = g_variant_new ("(u)", pid);
                goto exit;
              }

          case KDBUS_ITEM_CREDS:

            if (flag == G_BUS_CREDS_UID)
              {
                guint uid = item->creds.uid;
                result = g_variant_new ("(u)", uid);
                goto exit;
              }

          case KDBUS_ITEM_SECLABEL:
          case KDBUS_ITEM_PID_COMM:
          case KDBUS_ITEM_TID_COMM:
          case KDBUS_ITEM_EXE:
          case KDBUS_ITEM_CMDLINE:
          case KDBUS_ITEM_CGROUP:
          case KDBUS_ITEM_CAPS:
          case KDBUS_ITEM_AUDIT:
          case KDBUS_ITEM_CONN_DESCRIPTION:
          case KDBUS_ITEM_AUXGROUPS:
          case KDBUS_ITEM_OWNED_NAME:
            break;
        }
   }

exit:
  g_kdbus_free_data (worker, cmd->offset);
  return result;
}


/**
 * _g_kdbus_GetNameOwner:
 *
 */
GVariant *
_g_kdbus_GetNameOwner (GKDBusWorker  *worker,
                       const gchar      *name,
                       GError          **error)
{
  return g_kdbus_GetConnInfo_internal (worker,
                                       name,
                                       G_BUS_CREDS_UNIQUE_NAME,
                                       error);
}


/**
 * _g_kdbus_GetConnectionUnixProcessID:
 *
 */
GVariant *
_g_kdbus_GetConnectionUnixProcessID (GKDBusWorker  *worker,
                                     const gchar      *name,
                                     GError          **error)
{
  return g_kdbus_GetConnInfo_internal (worker,
                                       name,
                                       G_BUS_CREDS_PID,
                                       error);
}


/**
 * _g_kdbus_GetConnectionUnixUser:
 *
 */
GVariant *
_g_kdbus_GetConnectionUnixUser (GKDBusWorker  *worker,
                                const gchar      *name,
                                GError          **error)
{
  return g_kdbus_GetConnInfo_internal (worker,
                                       name,
                                       G_BUS_CREDS_UID,
                                       error);
}


/**
 * g_kdbus_bloom_add_data:
 * Based on bus-bloom.c from systemd
 * http://cgit.freedesktop.org/systemd/systemd/tree/src/libsystemd/sd-bus/bus-bloom.c
 */
static void
g_kdbus_bloom_add_data (GKDBusWorker  *worker,
                        guint64        bloom_data [],
                        const void    *data,
                        gsize          n)
{
  guint8 hash[8];
  guint64 bit_num;
  guint bytes_num = 0;
  guint cnt_1, cnt_2;
  guint hash_index = 0;

  guint c = 0;
  guint64 p = 0;

  bit_num = worker->bloom_size * 8;

  if (bit_num > 1)
    bytes_num = ((__builtin_clzll(bit_num) ^ 63U) + 7) / 8;

  for (cnt_1 = 0; cnt_1 < (worker->bloom_n_hash); cnt_1++)
    {
      for (cnt_2 = 0, hash_index = 0; cnt_2 < bytes_num; cnt_2++)
        {
          if (c <= 0)
            {
              _g_siphash24(hash, data, n, hash_keys[hash_index++]);
              c += 8;
            }

          p = (p << 8ULL) | (guint64) hash[8 - c];
          c--;
        }

      p &= bit_num - 1;
      bloom_data[p >> 6] |= 1ULL << (p & 63);
    }
}


/**
 * g_kdbus_bloom_add_pair:
 *
 */
static void
g_kdbus_bloom_add_pair (GKDBusWorker  *worker,
                        guint64        bloom_data [],
                        const gchar   *parameter,
                        const gchar   *value)
{
  gchar buf[1024];
  gsize size;

  size = strlen(parameter) + strlen(value) + 1;
  if (size > 1024)
    return;

  strcpy(stpcpy(stpcpy(buf, parameter), ":"), value);
  g_kdbus_bloom_add_data(worker, bloom_data, buf, size);
}


/**
 * g_kdbus_bloom_add_prefixes:
 *
 */
static void
g_kdbus_bloom_add_prefixes (GKDBusWorker  *worker,
                            guint64        bloom_data [],
                            const gchar   *parameter,
                            const gchar   *value,
                            gchar          separator)
{
  gchar buf[1024];
  gsize size;

  size = strlen(parameter) + strlen(value) + 1;
  if (size > 1024)
    return;

  strcpy(stpcpy(stpcpy(buf, parameter), ":"), value);

  for (;;)
    {
      gchar *last_sep;
      last_sep = strrchr(buf, separator);
      if (!last_sep || last_sep == buf)
        break;

      *last_sep = 0;
      g_kdbus_bloom_add_data(worker, bloom_data, buf, last_sep-buf);
    }
}


/**
 * _g_kdbus_AddMatch:
 *
 */
void
_g_kdbus_AddMatch (GKDBusWorker  *worker,
                   const gchar   *match_rule,
                   guint64        cookie)
{
  Match *match;
  MatchElement *element;
  const gchar *sender_name;
  gsize sender_len, size;
  struct kdbus_cmd_match *cmd;
  struct kdbus_item *item;
  guint64 *bloom;
  guint64 src_id;
  gchar *type;
  gint cnt, ret;

  if (match_rule[0] == '-')
    return;

  match = match_new (match_rule);
  if (!match)
    {
      match_free (match);
      return;
    }

  sender_name = NULL;
  src_id = KDBUS_MATCH_ID_ANY;

  bloom = g_alloca0 (worker->bloom_size);
  size = KDBUS_ALIGN8 (G_STRUCT_OFFSET (struct kdbus_cmd_match, items));
  match = match_new (match_rule);

  for (cnt = 0; cnt < match->n_elements; cnt++)
    {
      element = &match->elements[cnt];
      switch (element->type)
        {
          case MATCH_ELEMENT_SENDER:
            if (g_dbus_is_unique_name(element->value))
              {
                src_id = g_ascii_strtoull ((element->value)+3, NULL, 10);
                size += KDBUS_ALIGN8 (G_STRUCT_OFFSET (struct kdbus_item, id) + sizeof(src_id));
              }
            else if (g_dbus_is_name (element->value))
              {
                sender_name = element->value;
                sender_len = strlen(element->value) + 1;
                size += KDBUS_ALIGN8 (G_STRUCT_OFFSET (struct kdbus_item, str) + sender_len);
              }
            else
              {
                g_critical ("Error while adding a match");
                match_free (match);
                return;
              }
            break;

          case MATCH_ELEMENT_TYPE:
            g_kdbus_bloom_add_pair (worker, bloom, "message-type", element->value);
            break;

          case MATCH_ELEMENT_INTERFACE:
            g_kdbus_bloom_add_pair (worker, bloom, "interface", element->value);
            break;

          case MATCH_ELEMENT_MEMBER:
            g_kdbus_bloom_add_pair (worker, bloom, "member", element->value);
            break;

          case MATCH_ELEMENT_PATH:
            g_kdbus_bloom_add_pair (worker, bloom, "path", element->value);
            break;

          case MATCH_ELEMENT_PATH_NAMESPACE:
            if (g_strcmp0 (element->value, "/"))
              g_kdbus_bloom_add_pair (worker, bloom, "path-slash-prefix", element->value);
            break;

          case MATCH_ELEMENT_ARGN:
            asprintf (&type, "arg%u", element->arg);
            g_kdbus_bloom_add_pair (worker, bloom, type, element->value);
            free (type);
            break;

          case MATCH_ELEMENT_ARGNPATH:
            asprintf (&type, "arg%u-slash-prefix", element->arg);
            g_kdbus_bloom_add_pair (worker, bloom, type, element->value);
            free (type);
            break;

          case MATCH_ELEMENT_ARG0NAMESPACE:
            g_kdbus_bloom_add_pair (worker, bloom, "arg0-dot-prefix", element->value);
            break;

          case MATCH_ELEMENT_DESTINATION:
          case MATCH_ELEMENT_EAVESDROP:
            break;
        }
    }

  size += KDBUS_ALIGN8 (G_STRUCT_OFFSET (struct kdbus_item, data64) + worker->bloom_size);
  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->cookie = cookie;

  item = cmd->items;
  item->size = G_STRUCT_OFFSET(struct kdbus_item, data64) + worker->bloom_size;
  item->type = KDBUS_ITEM_BLOOM_MASK;
  memcpy(item->data64, bloom, worker->bloom_size);
  item = KDBUS_ITEM_NEXT(item);

  if (src_id != KDBUS_MATCH_ID_ANY)
    {
      item->size = G_STRUCT_OFFSET (struct kdbus_item, id) + sizeof(src_id);
      item->type = KDBUS_ITEM_ID;
      item->id = src_id;
      item = KDBUS_ITEM_NEXT(item);
    }

  if (sender_name)
    {
      item->size = G_STRUCT_OFFSET (struct kdbus_item, str) + sender_len;
      item->type = KDBUS_ITEM_NAME;
      memcpy (item->str, sender_name, sender_len);
    }

  ret = ioctl(worker->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (ret < 0)
    g_critical ("Error while adding a match: %d", (int) errno);

  match_free (match);
}


/**
 * _g_kdbus_RemoveMatch:
 *
 */
void
_g_kdbus_RemoveMatch (GKDBusWorker  *worker,
                      guint64        cookie)
{
  struct kdbus_cmd_match cmd = {
    .size = sizeof(cmd),
    .cookie = cookie
  };
  gint ret;

  g_print ("Unsubscribe match entry with cookie - %d\n", (int)cookie);
  ret = ioctl(worker->fd, KDBUS_CMD_MATCH_REMOVE, &cmd);
  if (ret < 0)
    g_warning ("Error while removing a match: %d\n", errno);
}


/**
 * _g_kdbus_subscribe_name_owner_changed_internal:
 *
 */
static void
_g_kdbus_subscribe_name_owner_changed_internal (GKDBusWorker  *worker,
                                                const gchar   *name,
                                                const gchar   *old_name,
                                                const gchar   *new_name,
                                                guint64        cookie)
{
  struct kdbus_item *item;
  struct kdbus_cmd_match *cmd;
  gssize size, len;
  gint ret;
  guint64 old_id = 0;
  guint64 new_id = KDBUS_MATCH_ID_ANY;

  if (name)
    len = strlen(name) + 1;
  else
    len = 0;

  size = KDBUS_ALIGN8(G_STRUCT_OFFSET (struct kdbus_cmd_match, items) +
                      G_STRUCT_OFFSET (struct kdbus_item, name_change) +
                      G_STRUCT_OFFSET (struct kdbus_notify_name_change, name) + len);

  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->cookie = cookie;
  item = cmd->items;

  if (old_name == NULL)
    {
      old_id = KDBUS_MATCH_ID_ANY;
    }
  else
    {
      if (g_dbus_is_unique_name(old_name))
        old_id = strtoull (old_name + 3, NULL, 10);
      else
        return;
    }

  if (new_name == NULL)
    {
      new_id = KDBUS_MATCH_ID_ANY;
    }
  else
    {
      if (g_dbus_is_unique_name(new_name))
        new_id = strtoull (new_name + 3, NULL, 10);
      else
        return;
    }

  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->cookie = cookie;
  item = cmd->items;

  /* KDBUS_ITEM_NAME_CHANGE */
  item->type = KDBUS_ITEM_NAME_CHANGE;
  item->name_change.old_id.id = old_id;
  item->name_change.new_id.id = new_id;

  if (name)
    memcpy(item->name_change.name, name, len);

  item->size = G_STRUCT_OFFSET (struct kdbus_item, name_change) +
               G_STRUCT_OFFSET(struct kdbus_notify_name_change, name) + len;
  item = KDBUS_ITEM_NEXT(item);

  ret = ioctl(worker->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (ret < 0)
    g_warning ("ERROR - %d\n", (int) errno);
}


/**
 * _g_kdbus_subscribe_name_acquired:
 *
 */
void
_g_kdbus_subscribe_name_acquired (GKDBusWorker  *worker,
                                  const gchar   *name,
                                  guint64        cookie)
{
  struct kdbus_item *item;
  struct kdbus_cmd_match *cmd;
  gssize size, len;
  gint ret;

  g_print ("Subscribe 'NameAcquired': name - %s ; cookie - %d\n", name, (int)cookie);
  if (name)
    len = strlen(name) + 1;
  else
    len = 0;

  size = KDBUS_ALIGN8(G_STRUCT_OFFSET (struct kdbus_cmd_match, items) +
                      G_STRUCT_OFFSET (struct kdbus_item, name_change) +
                      G_STRUCT_OFFSET (struct kdbus_notify_name_change, name) + len);

  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->cookie = cookie;
  item = cmd->items;

  /* KDBUS_ITEM_NAME_ADD */
  item->type = KDBUS_ITEM_NAME_ADD;
  item->name_change.old_id.id = KDBUS_MATCH_ID_ANY;
  item->name_change.new_id.id = worker->unique_id;

  if (name)
    memcpy(item->name_change.name, name, len);

  item->size = G_STRUCT_OFFSET (struct kdbus_item, name_change) +
               G_STRUCT_OFFSET(struct kdbus_notify_name_change, name) + len;
  item = KDBUS_ITEM_NEXT(item);

  ret = ioctl(worker->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (ret < 0)
    g_warning ("ERROR - %d\n", (int) errno);

  _g_kdbus_subscribe_name_owner_changed_internal (worker, name, NULL, worker->unique_name, cookie);
}


/**
 * _g_kdbus_subscribe_name_lost:
 *
 */
void
_g_kdbus_subscribe_name_lost (GKDBusWorker  *worker,
                              const gchar   *name,
                              guint64        cookie)
{
  struct kdbus_item *item;
  struct kdbus_cmd_match *cmd;
  gssize size, len;
  gint ret;

  g_print ("Subscribe 'NameLost': name - %s ; cookie - %d\n", name, (int)cookie);
  if (name)
    len = strlen(name) + 1;
  else
    len = 0;

  size = KDBUS_ALIGN8(G_STRUCT_OFFSET (struct kdbus_cmd_match, items) +
                      G_STRUCT_OFFSET (struct kdbus_item, name_change) +
                      G_STRUCT_OFFSET (struct kdbus_notify_name_change, name) + len);

  cmd = g_alloca0 (size);
  cmd->size = size;
  cmd->cookie = cookie;
  item = cmd->items;

  /* KDBUS_ITEM_NAME_REMOVE */
  item->type = KDBUS_ITEM_NAME_REMOVE;
  item->name_change.old_id.id = worker->unique_id;
  item->name_change.new_id.id = KDBUS_MATCH_ID_ANY;

  if (name)
    memcpy(item->name_change.name, name, len);

  item->size = G_STRUCT_OFFSET (struct kdbus_item, name_change) +
               G_STRUCT_OFFSET(struct kdbus_notify_name_change, name) + len;
  item = KDBUS_ITEM_NEXT(item);

  ret = ioctl(worker->fd, KDBUS_CMD_MATCH_ADD, cmd);
  if (ret < 0)
    g_warning ("ERROR - %d\n", (int) errno);

  _g_kdbus_subscribe_name_owner_changed_internal (worker, name, worker->unique_name, NULL, cookie);
}


/**
 *
 *
 */
void
_g_kdbus_subscribe_name_owner_changed (GKDBusWorker  *worker,
                                       const gchar   *name,
                                       guint64        cookie)
{
  g_print ("NameOwnerChanged subscription\n");
}


/**
 * g_kdbus_setup_bloom:
 * Based on bus-bloom.c from systemd
 * http://cgit.freedesktop.org/systemd/systemd/tree/src/libsystemd/sd-bus/bus-bloom.c
 */
static void
g_kdbus_setup_bloom (GKDBusWorker                     *worker,
                     GDBusMessage               *dbus_msg,
                     struct kdbus_bloom_filter  *bloom_filter)
{
  GVariant *body;

  const gchar *message_type;
  const gchar *interface;
  const gchar *member;
  const gchar *path;

  void *bloom_data;

  body = g_dbus_message_get_body (dbus_msg);
  message_type = _g_dbus_enum_to_string (G_TYPE_DBUS_MESSAGE_TYPE, g_dbus_message_get_message_type (dbus_msg));
  interface = g_dbus_message_get_interface (dbus_msg);
  member = g_dbus_message_get_member (dbus_msg);
  path = g_dbus_message_get_path (dbus_msg);

  bloom_data = bloom_filter->data;
  memset (bloom_data, 0, worker->bloom_size);
  bloom_filter->generation = 0;

  g_kdbus_bloom_add_pair(worker, bloom_data, "message-type", message_type);

  if (interface)
    g_kdbus_bloom_add_pair(worker, bloom_data, "interface", interface);

  if (member)
    g_kdbus_bloom_add_pair(worker, bloom_data, "member", member);

  if (path)
    {
      g_kdbus_bloom_add_pair(worker, bloom_data, "path", path);
      g_kdbus_bloom_add_pair(worker, bloom_data, "path-slash-prefix", path);
      g_kdbus_bloom_add_prefixes(worker, bloom_data, "path-slash-prefix", path, '/');
    }

  if (body != NULL)
    {
      const GVariantType *body_type;
      const GVariantType *arg_type;
      guint cnt;

      body_type = g_variant_get_type (body);

      for (arg_type = g_variant_type_first (body_type), cnt = 0;
           arg_type;
           arg_type = g_variant_type_next (arg_type), cnt++)
        {
          gchar type_char = g_variant_type_peek_string (arg_type)[0];
          gchar buf[sizeof("arg")-1 + 2 + sizeof("-slash-prefix")];
          const gchar *str;
          GVariant *child;
          gchar *e;

          if (type_char != 's' && type_char != 'o')
            /* XXX: kdbus docs say "stop after first non-string" but I
             * think they're wrong (vs. dbus-1 compat)...
             */
            continue;

          child = g_variant_get_child_value (body, cnt);
          str = g_variant_get_string (child, NULL);

          e = stpcpy(buf, "arg");
          if (cnt < 10)
            *(e++) = '0' + (char) cnt;
          else
            {
              *(e++) = '0' + (char) (cnt / 10);
              *(e++) = '0' + (char) (cnt % 10);
            }

          /* We add this one for both strings and object paths */
          strcpy(e, "-slash-prefix");
          g_kdbus_bloom_add_prefixes(worker, bloom_data, buf, str, '/');

          /* But the others are only for strings */
          if (type_char == 's')
            {
              strcpy(e, "-dot-prefix");
              g_kdbus_bloom_add_prefixes(worker, bloom_data, buf, str, '.');

              *e = 0;
              g_kdbus_bloom_add_pair(worker, bloom_data, buf, str);
            }

          g_variant_unref (child);
        }
    }
}


/**
 *
 *
 */
static void
g_kdbus_translate_id_change (GKDBusWorker       *worker,
                             struct kdbus_item  *item)
{
  g_error ("TODO: translate_id_change\n");
}


/**
 *
 *
 */
static void
g_kdbus_translate_name_change (GKDBusWorker       *worker,
                               struct kdbus_item  *item)
{
  GDBusMessage *signal_message;

  signal_message = NULL;

  /* NameAcquired */
  if ((item->type == KDBUS_ITEM_NAME_ADD) ||
      (item->type == KDBUS_ITEM_NAME_CHANGE && ((guint64)item->name_change.new_id.id == worker->unique_id)))
    {
      signal_message = g_dbus_message_new_signal ("/org/freedesktop/DBus",
                                                  "org.freedesktop.DBus",
                                                  "NameAcquired");

      g_dbus_message_set_sender (signal_message, "org.freedesktop.DBus");
      g_dbus_message_set_body (signal_message,
                               g_variant_new ("(s)", item->name_change.name));

      (* worker->message_received_callback) (signal_message, worker->user_data);
      g_object_unref (signal_message);
    }

  /* NameLost */
  if ((item->type == KDBUS_ITEM_NAME_REMOVE) ||
      (item->type == KDBUS_ITEM_NAME_CHANGE && ((guint64)item->name_change.old_id.id == worker->unique_id)))
    {
      GDBusMessage *signal_message;

      signal_message = g_dbus_message_new_signal ("/org/freedesktop/DBus",
                                                  "org.freedesktop.DBus",
                                                  "NameLost");

      g_dbus_message_set_sender (signal_message, "org.freedesktop.DBus");
      g_dbus_message_set_body (signal_message,
                               g_variant_new ("(s)", item->name_change.name));

      (* worker->message_received_callback) (signal_message, worker->user_data);
      g_object_unref (signal_message);
    }

  /* NameOwnerChanged */
  /* TODO */
}


/**
 *
 *
 */
static void
g_kdbus_translate_kernel_reply (GKDBusWorker       *worker,
                                struct kdbus_item  *item)
{
  g_error ("TODO: translate_kernel_reply\n");
}


/**
 * g_kdbus_decode_kernel_msg:
 *
 */
static void
g_kdbus_decode_kernel_msg (GKDBusWorker           *worker,
                           struct kdbus_msg *msg)
{
  struct kdbus_item *item = NULL;

  KDBUS_ITEM_FOREACH(item, msg, items)
    {
     switch (item->type)
        {
          case KDBUS_ITEM_ID_ADD:
          case KDBUS_ITEM_ID_REMOVE:
            g_kdbus_translate_id_change (worker, item);
            break;

          case KDBUS_ITEM_NAME_ADD:
          case KDBUS_ITEM_NAME_REMOVE:
          case KDBUS_ITEM_NAME_CHANGE:
            g_kdbus_translate_name_change (worker, item);
            break;

          case KDBUS_ITEM_REPLY_TIMEOUT:
          case KDBUS_ITEM_REPLY_DEAD:
            g_kdbus_translate_kernel_reply (worker, item);
            break;

          case KDBUS_ITEM_TIMESTAMP:
            break;

          default:
            g_warning ("Unknown field in kernel message - %lld", item->type);
       }
    }
}


/**
 * g_kdbus_decode_dbus_msg:
 *
 */
static GDBusMessage *
g_kdbus_decode_dbus_msg (GKDBusWorker           *worker,
                         struct kdbus_msg *msg)
{
  GDBusMessage *message;
  struct kdbus_item *item;
  gssize data_size = 0;
  GArray *body_vectors;
  gsize body_size;
  GVariant *body;
  gchar *tmp;
  guint i;
  GVariant *parts[2];
  GVariantIter *fields_iter;
  guint8 endianness, type, flags, version;
  guint64 key;
  GVariant *value;
  guint64 serial;


  message = g_dbus_message_new ();

  body_vectors = g_array_new (FALSE, FALSE, sizeof (GVariantVector));

  tmp = g_strdup_printf (":1.%"G_GUINT64_FORMAT, (guint64) msg->src_id);
  g_dbus_message_set_sender (message, tmp);
  g_free (tmp);

  item = msg->items;
  body_size = 0;

  KDBUS_ITEM_FOREACH(item, msg, items)
    {
      if (item->size <= KDBUS_ITEM_HEADER_SIZE)
        g_error("[KDBUS] %llu bytes - invalid data record\n", item->size);

      data_size = item->size - KDBUS_ITEM_HEADER_SIZE;

      switch (item->type)
        {
         /* KDBUS_ITEM_DST_NAME */
         case KDBUS_ITEM_DST_NAME:
           /* Classic D-Bus doesn't make this known to the receiver, so
            * we don't do it here either (for compatibility with the
            * fallback case).
            */
           break;

        /* KDBUS_ITEM_PALOAD_OFF */
        case KDBUS_ITEM_PAYLOAD_OFF:
          {
            GVariantVector vector;
            gsize flavour;

            /* We want to make sure the bytes are aligned the same as
             * they would be if they appeared in a contiguously
             * allocated chunk of aligned memory.
             *
             * We decide what the alignment 'should' be by consulting
             * body_size, which has been tracking the total size of the
             * message up to this point.
             *
             * We then play around with the pointer by removing as many
             * bytes as required to get it to the proper alignment (and
             * copy extra bytes accordingly).  This means that we will
             * grab some extra data in the 'bytes', but it won't be
             * shared with GVariant (which means there is no chance of
             * it being accidentally retransmitted).
             *
             * The kernel does the same thing, so make sure we get the
             * expected result.  Because of the kernel doing the same,
             * the result is that we will always be rounding-down to a
             * multiple of 8 for the pointer, which means that the
             * pointer will always be valid, assuming the original
             * address was.
             *
             * We could fix this with a new GBytes constructor that took
             * 'flavour' as a parameter, but it's not worth it...
             */
            flavour = body_size & 7;
            g_assert ((item->vec.offset & 7) == flavour);

            vector.gbytes = g_bytes_new (((guchar *) msg) + item->vec.offset - flavour, item->vec.size + flavour);
            vector.data.pointer = g_bytes_get_data (vector.gbytes, NULL);
            vector.data.pointer += flavour;
            vector.size = item->vec.size;

            g_array_append_val (body_vectors, vector);
            body_size += vector.size;
          }
          break;

        /* KDBUS_ITEM_PAYLOAD_MEMFD */
        case KDBUS_ITEM_PAYLOAD_MEMFD:
          {
            GVariantVector vector;
            const guchar *data;
            gsize size;

            vector.gbytes = g_bytes_new_take_zero_copy_fd (item->memfd.fd);
            data = g_bytes_get_data (vector.gbytes, &size);

            g_assert (item->memfd.start + item->memfd.size <= size);

            vector.data.pointer = data + item->memfd.start;
            vector.size = item->memfd.size;

            g_array_append_val (body_vectors, vector);
            body_size += vector.size;
          }
          break;

        /* KDBUS_ITEM_FDS */
        case KDBUS_ITEM_FDS:
          {
            GUnixFDList *fd_list;

            fd_list = g_unix_fd_list_new_from_array (item->fds, data_size / sizeof (int));
            g_dbus_message_set_unix_fd_list (message, fd_list);
            g_object_unref (fd_list);
          }
          break;

        /* All of the following items, like CMDLINE,
           CGROUP, etc. need some GDBUS API extensions and
           should be implemented in the future */
        case KDBUS_ITEM_TIMESTAMP:
          {
            /* g_print ("time: seq %llu mon %llu real %llu\n",
                     item->timestamp.seqnum, item->timestamp.monotonic_ns, item->timestamp.realtime_ns); */

            //g_dbus_message_set_timestamp (message, item->timestamp.monotonic_ns / 1000);
            //g_dbus_message_set_serial (message, item->timestamp.seqnum);
            break;
          }

        case KDBUS_ITEM_CREDS:
          {
            /* g_print ("creds: u%llu eu %llu su%llu fsu%llu g%llu eg%llu sg%llu fsg%llu\n",
                     item->creds.uid, item->creds.euid, item->creds.suid, item->creds.fsuid,
                     item->creds.gid, item->creds.egid, item->creds.sgid, item->creds.fsgid); */
            break;
          }

        case KDBUS_ITEM_PIDS:
        case KDBUS_ITEM_PID_COMM:
        case KDBUS_ITEM_TID_COMM:
        case KDBUS_ITEM_EXE:
        case KDBUS_ITEM_CMDLINE:
        case KDBUS_ITEM_CGROUP:
        case KDBUS_ITEM_AUDIT:
        case KDBUS_ITEM_CAPS:
        case KDBUS_ITEM_SECLABEL:
        case KDBUS_ITEM_CONN_DESCRIPTION:
        case KDBUS_ITEM_AUXGROUPS:
        case KDBUS_ITEM_OWNED_NAME:
        case KDBUS_ITEM_NAME:
          //g_print ("unhandled %04x\n", (int) item->type);
          break;

        default:
          g_error ("[KDBUS] DBUS_PAYLOAD: Unknown filed - %lld", item->type);
          break;
        }
    }

  body = GLIB_PRIVATE_CALL(g_variant_from_vectors) (G_VARIANT_TYPE ("((yyyyuta{tv})v)"),
                                                    (GVariantVector *) body_vectors->data,
                                                    body_vectors->len, body_size, FALSE);
  g_assert (body);

  for (i = 0; i < body_vectors->len; i++)
    g_bytes_unref (g_array_index (body_vectors, GVariantVector, i).gbytes);

  g_array_free (body_vectors, TRUE);

  parts[0] = g_variant_get_child_value (body, 0);
  parts[1] = g_variant_get_child_value (body, 1);
  g_variant_unref (body);

  g_variant_get (parts[0], "(yyyyuta{tv})", &endianness, &type, &flags, &version, NULL, &serial, &fields_iter);
  g_variant_unref (parts[0]);

  while (g_variant_iter_loop (fields_iter, "{tv}", &key, &value))
    g_dbus_message_set_header (message, key, value);

  g_dbus_message_set_flags (message, flags);
  g_dbus_message_set_serial (message, serial);
  g_dbus_message_set_message_type (message, type);

  //if (g_dbus_message_get_header (message, G_DBUS_MESSAGE_HEADER_FIELD_SIGNATURE) != NULL)
  //  {
      body = g_variant_get_variant (parts[1]);
      g_dbus_message_set_body (message, body);
      g_variant_unref (body);
  //  }
  g_variant_unref (parts[1]);

  //g_print ("Received:\n%s\n", g_dbus_message_print (message, 2));

  (* worker->message_received_callback) (message, worker->user_data);

  g_object_unref (message);

  return 0;
}


/**
 * _g_kdbus_receive:
 *
 */
static gssize
_g_kdbus_receive (GKDBusWorker        *kdbus,
                  GCancellable  *cancellable,
                  GError       **error)
{
  struct kdbus_cmd_recv recv;
  struct kdbus_msg *msg;

  memset (&recv, 0, sizeof recv);
  recv.size = sizeof (recv);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return -1;

again:
    if (ioctl(kdbus->fd, KDBUS_CMD_RECV, &recv) < 0)
      {
        if (errno == EINTR)
          goto again;

        if (errno == EAGAIN)
          return 0;

        g_warning ("in holding pattern over %d %d\n", kdbus->fd, errno);
        while (1)
          sleep(1);

        g_set_error (error, G_IO_ERROR,
                     g_io_error_from_errno (errno),
                     _("Error while receiving message: %s"),
                     g_strerror (errno));
        return -1;
      }

   msg = (struct kdbus_msg *)((guint8 *)kdbus->kdbus_buffer + recv.msg.offset);

   if (msg->payload_type == KDBUS_PAYLOAD_DBUS)
     g_kdbus_decode_dbus_msg (kdbus, msg);
   else if (msg->payload_type == KDBUS_PAYLOAD_KERNEL)
     g_kdbus_decode_kernel_msg (kdbus, msg);
   else
     {
       g_set_error (error,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_FAILED,
                    _("Received unknown payload type"));
       return -1;
     }

  g_kdbus_free_data (kdbus, recv.msg.offset);

  return 0;
}

static gboolean
g_kdbus_msg_append_item (struct kdbus_msg *msg,
                         gsize             type,
                         gconstpointer     data,
                         gsize             size)
{
  struct kdbus_item *item;
  gsize item_size;

  item_size = size + G_STRUCT_OFFSET(struct kdbus_item, data);

  if (msg->size + item_size > KDBUS_MSG_MAX_SIZE)
    return FALSE;

  /* align */
  msg->size += (-msg->size) & 7;
  item = (struct kdbus_item *) ((guchar *) msg + msg->size);
  item->type = type;
  item->size = item_size;
  memcpy (item->data, data, size);

  msg->size += item_size;

  return TRUE;
}

static gboolean
g_kdbus_msg_append_payload_vec (struct kdbus_msg *msg,
                                gconstpointer     data,
                                gsize             size)
{
  struct kdbus_vec vec = {
    .size = size,
    .address = (gsize) data
  };

  return g_kdbus_msg_append_item (msg, KDBUS_ITEM_PAYLOAD_VEC, &vec, sizeof vec);
}

static gboolean
g_kdbus_msg_append_payload_memfd (struct kdbus_msg *msg,
                                  gint              fd,
                                  gsize             offset,
                                  gsize             size)
{
  struct kdbus_memfd mfd = {
   .start = offset,
   .size = size,
   .fd = fd,
  };

  return g_kdbus_msg_append_item (msg, KDBUS_ITEM_PAYLOAD_MEMFD, &mfd, sizeof mfd);
}

static struct kdbus_bloom_filter *
g_kdbus_msg_append_bloom (struct kdbus_msg *msg,
                          gsize             size)
{
  struct kdbus_item *bloom_item;
  gsize bloom_item_size;

  bloom_item_size = G_STRUCT_OFFSET (struct kdbus_item, bloom_filter) +
                    G_STRUCT_OFFSET (struct kdbus_bloom_filter, data) +
                    size;
  if (msg->size + bloom_item_size > KDBUS_MSG_MAX_SIZE)
    return NULL;

  /* align */
  msg->size += (-msg->size) & 7;
  bloom_item = (struct kdbus_item *) ((guchar *) msg + msg->size);

  /* set size and type */
  bloom_item->size = bloom_item_size;
  bloom_item->type = KDBUS_ITEM_BLOOM_FILTER;

  msg->size += bloom_item->size;
  return &bloom_item->bloom_filter;
}

#if 0
#include "dbusheader.h"

void dump_header (gconstpointer data, gsize size) ;
void
dump_header (gconstpointer data,
             gsize size)
{
  GDBusMessageHeaderFieldsIterator iter;
  GDBusMessageHeader header;

  header = g_dbus_message_header_new (data, size);
  g_print ("header e/%c t/%u f/x%x v/%u s/%"G_GUINT64_FORMAT"\n",
           g_dbus_message_header_get_endian (header),
           g_dbus_message_header_get_type (header),
           g_dbus_message_header_get_flags (header),
           g_dbus_message_header_get_version (header),
           g_dbus_message_header_get_serial (header));

  iter = g_dbus_message_header_iterate_fields (header);

  while (g_dbus_message_header_fields_iterator_next (&iter))
    {
      const gchar *string;
      guint64 reply_to;
      guint64 key;

      key = g_dbus_message_header_fields_iterator_get_key (iter);

      switch (key)
        {
          case G_DBUS_MESSAGE_HEADER_FIELD_PATH:
            if (g_dbus_message_header_fields_iterator_get_value_as_object_path (iter, &string))
              g_print ("  path: %s\n", string);
            else
              g_print ("  path: <<invalid string>>\n");
            break;

          case G_DBUS_MESSAGE_HEADER_FIELD_INTERFACE:
            if (g_dbus_message_header_fields_iterator_get_value_as_string (iter, &string))
              g_print ("  interface: %s\n", string);
            else
              g_print ("  interface: <<invalid string>>\n");
            break;

          case G_DBUS_MESSAGE_HEADER_FIELD_MEMBER:
            if (g_dbus_message_header_fields_iterator_get_value_as_string (iter, &string))
              g_print ("  member: %s\n", string);
            else
              g_print ("  member: <<invalid string>>\n");
            break;

          case G_DBUS_MESSAGE_HEADER_FIELD_ERROR_NAME:
            if (g_dbus_message_header_fields_iterator_get_value_as_string (iter, &string))
              g_print ("  error: %s\n", string);
            else
              g_print ("  error: <<invalid string>>\n");
            break;

          case G_DBUS_MESSAGE_HEADER_FIELD_REPLY_SERIAL:
            if (g_dbus_message_header_fields_iterator_get_value_as_string (iter, &string))
              g_print ("  serial: %s\n", string);
            else
              g_print ("  serial: <<invalid string>>\n");
            break;

          case G_DBUS_MESSAGE_HEADER_FIELD_DESTINATION:
            if (g_dbus_message_header_fields_iterator_get_value_as_string (iter, &string))
              g_print ("  destination: %s\n", string);
            else
              g_print ("  destination: <<invalid string>>\n");
            break;

          case G_DBUS_MESSAGE_HEADER_FIELD_SENDER:
            if (g_dbus_message_header_fields_iterator_get_value_as_string (iter, &string))
              g_print ("  sender: %s\n", string);
            else
              g_print ("  sender: <<invalid string>>\n");
            break;

          default:
            g_print ("unknown field code %"G_GUINT64_FORMAT"\n", key);
            g_assert_not_reached ();
        }
    }

  g_print ("\n");

}
#endif

/**
 * _g_kdbus_send:
 * Returns: size of data sent or -1 when error
 */
static gboolean
_g_kdbus_send (GKDBusWorker        *kdbus,
               GDBusMessage  *message,
               GError       **error)
{
  struct kdbus_msg *msg = alloca (KDBUS_MSG_MAX_SIZE);
  GVariantVectors body_vectors;
  struct kdbus_cmd_send send;
  const gchar *dst_name;

  g_return_val_if_fail (G_IS_KDBUS_WORKER (kdbus), -1);

  /* fill in as we go... */
  memset (msg, 0, sizeof (struct kdbus_msg));
  msg->size = sizeof (struct kdbus_msg);
  msg->payload_type = KDBUS_PAYLOAD_DBUS;
  msg->src_id = kdbus->unique_id;
  msg->cookie = g_dbus_message_get_serial(message);

  /* Message destination */
  {
    dst_name = g_dbus_message_get_destination (message);

    if (dst_name != NULL)
      {
        if (g_dbus_is_unique_name (dst_name))
          {
            if (dst_name[1] != '1' || dst_name[2] != '.')
              {
                g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_NAME_HAS_NO_OWNER,
                             "Invalid unique D-Bus name '%s'", dst_name);
                return FALSE;
              }

            /* We already know that it passes the checks for unique
             * names, so no need to perform error checking on strtoull.
             */
            msg->dst_id = strtoull (dst_name + 3, NULL, 10);
            dst_name = NULL;
          }
        else
          {
            g_kdbus_msg_append_item (msg, KDBUS_ITEM_DST_NAME, dst_name, strlen (dst_name) + 1);
            msg->dst_id = KDBUS_DST_ID_NAME;
          }
      }
    else
      msg->dst_id = KDBUS_DST_ID_BROADCAST;
  }

  /* File descriptors */
  {
    GUnixFDList *fd_list;

    fd_list = g_dbus_message_get_unix_fd_list (message);

    if (fd_list != NULL)
      {
        const gint *fds;
        gint n_fds;

        fds = g_unix_fd_list_peek_fds (fd_list, &n_fds);

        if (n_fds)
          g_kdbus_msg_append_item (msg, KDBUS_ITEM_FDS, fds, sizeof (gint) * n_fds);
      }
  }

  /* Message body */
  {
    struct dbus_fixed_header fh;
    GHashTableIter header_iter;
    GVariantBuilder builder;
    gpointer key, value;
    GVariant *parts[3];
    GVariant *body;

    fh.endian = (G_BYTE_ORDER == G_LITTLE_ENDIAN) ? 'l': 'B';
    fh.type = g_dbus_message_get_message_type (message);
    fh.flags = g_dbus_message_get_flags (message);
    fh.version = 2;
    fh.reserved = 0;
    fh.serial = g_dbus_message_get_serial (message);
    parts[0] = g_variant_new_from_data (DBUS_FIXED_HEADER_TYPE, &fh, sizeof fh, TRUE, NULL, NULL);

    g_dbus_message_init_header_iter (message, &header_iter);
    g_variant_builder_init (&builder, DBUS_EXTENDED_HEADER_TYPE);

    /* We set the sender field to the correct value for ourselves */
    g_variant_builder_add (&builder, "{tv}",
                           (guint64) G_DBUS_MESSAGE_HEADER_FIELD_SENDER,
                           g_variant_new_printf (":1.%"G_GUINT64_FORMAT, kdbus->unique_id));

    while (g_hash_table_iter_next (&header_iter, &key, &value))
      {
        guint64 key_int = (gsize) key;

        switch (key_int)
          {
            /* These are the normal header fields that get passed
             * straight through.
             */
            case G_DBUS_MESSAGE_HEADER_FIELD_PATH:
            case G_DBUS_MESSAGE_HEADER_FIELD_INTERFACE:
            case G_DBUS_MESSAGE_HEADER_FIELD_MEMBER:
            case G_DBUS_MESSAGE_HEADER_FIELD_ERROR_NAME:
            case G_DBUS_MESSAGE_HEADER_FIELD_REPLY_SERIAL:
            case G_DBUS_MESSAGE_HEADER_FIELD_DESTINATION:
              g_variant_builder_add (&builder, "{tv}", key_int, value);
              /* This is a little bit gross.
               *
               * We must send the header part of the message in a single
               * vector as per kdbus rules, but the GVariant serialiser
               * code will split any item >= 128 bytes into its own
               * vector to save the copy.
               *
               * No header field should be that big anyway... right?
               */
              g_assert_cmpint (g_variant_get_size (value), <, 128);
              continue;

            /* We send this one unconditionally, but set it ourselves */
            case G_DBUS_MESSAGE_HEADER_FIELD_SENDER:
              continue;

            /* We don't send these at all in GVariant format */
            case G_DBUS_MESSAGE_HEADER_FIELD_SIGNATURE:
            case G_DBUS_MESSAGE_HEADER_FIELD_NUM_UNIX_FDS:
              continue;

            default:
              g_assert_not_reached ();
          }
      }
    parts[1] = g_variant_builder_end (&builder);

    body = g_dbus_message_get_body (message);
    if (!body)
      body = g_variant_new ("()");
    parts[2] = g_variant_new_variant (body);

    body = g_variant_ref_sink (g_variant_new_tuple (parts, G_N_ELEMENTS (parts)));
    GLIB_PRIVATE_CALL(g_variant_to_vectors) (body, &body_vectors);

    /* Sanity check to make sure the header is really contiguous:
     *
     *  - we must have at least one vector in the output
     *  - the first vector must completely contain at least the header
     */
    g_assert_cmpint (body_vectors.vectors->len, >, 0);
    g_assert_cmpint (g_array_index (body_vectors.vectors, GVariantVector, 0).size, >=,
                     g_variant_get_size (parts[0]) + g_variant_get_size (parts[1]));

    g_variant_unref (body);
  }

  {
    guint i;

    for (i = 0; i < body_vectors.vectors->len; i++)
      {
        GVariantVector vector = g_array_index (body_vectors.vectors, GVariantVector, i);

        if (vector.gbytes)
          {
            gint fd;

            fd = g_bytes_get_zero_copy_fd (vector.gbytes);

            if (fd >= 0)
              {
                const guchar *bytes_data;
                gsize bytes_size;

                bytes_data = g_bytes_get_data (vector.gbytes, &bytes_size);

                if (bytes_data <= vector.data.pointer && vector.data.pointer + vector.size <= bytes_data + bytes_size)
                  {
                    if (!g_kdbus_msg_append_payload_memfd (msg, fd, vector.data.pointer - bytes_data, vector.size))
                      goto need_compact;
                  }
                else
                  {
                    if (!g_kdbus_msg_append_payload_vec (msg, vector.data.pointer, vector.size))
                      goto need_compact;
                  }
              }
            else
              {
                if (!g_kdbus_msg_append_payload_vec (msg, vector.data.pointer, vector.size))
                  goto need_compact;
              }
          }
        else
          if (!g_kdbus_msg_append_payload_vec (msg, body_vectors.extra_bytes->data + vector.data.offset, vector.size))
            goto need_compact;
      }
  }

  /*
   * set message flags
   */
  msg->flags = ((g_dbus_message_get_flags (message) & G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_EXPECT_REPLY) |
                ((g_dbus_message_get_flags (message) & G_DBUS_MESSAGE_FLAGS_NO_AUTO_START) ? KDBUS_MSG_NO_AUTO_START : 0);

  if ((msg->flags) & KDBUS_MSG_EXPECT_REPLY)
    msg->timeout_ns = 1000LU * g_get_monotonic_time() + KDBUS_TIMEOUT_NS;
  else
    msg->cookie_reply = g_dbus_message_get_reply_serial(message);

  if (g_dbus_message_get_message_type (message) == G_DBUS_MESSAGE_TYPE_SIGNAL)
    msg->flags |= KDBUS_MSG_SIGNAL;

  /*
   * append bloom filter item for broadcast signals
   */
  if (msg->dst_id == KDBUS_DST_ID_BROADCAST)
    {
      struct kdbus_bloom_filter *bloom_filter;

      bloom_filter = g_kdbus_msg_append_bloom (msg, kdbus->bloom_size);
      if (bloom_filter == NULL)
        goto need_compact;
      g_kdbus_setup_bloom (kdbus, message, bloom_filter);
    }

  send.size = sizeof (send);
  send.flags = 0;
  send.msg_address = (gsize) msg;

  /*
   * send message
   */
  if (ioctl(kdbus->fd, KDBUS_CMD_SEND, &send))
    {
      if (errno == ENXIO || errno == ESRCH)
        {
          g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN,
                       "Destination '%s' not known", dst_name);
        }
      else if (errno == EADDRNOTAVAIL)
        {
          g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN,
                       "No support for activation for name: %s", dst_name);
        }
      else if (errno == EXFULL)
        {
          g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
                       "The memory pool of the receiver is full");
        }
      else
        {
          g_error ("WTF? %d\n", errno);
          g_set_error (error, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                       "%s", strerror(errno));
        }
      return FALSE;
    }

  return TRUE;

need_compact:
  /* We end up here if:
   *  - too many kdbus_items
   *  - too large kdbus_msg size
   *  - too much vector data
   *
   * We need to compact the message before sending it.
   */
  g_assert_not_reached ();
}

GKDBusWorker *
g_kdbus_worker_new (const gchar  *address,
                    GError      **error)
{
  GKDBusWorker *worker;

  worker = g_object_new (G_TYPE_KDBUS_WORKER, NULL);
  if (!_g_kdbus_open (worker, address, error))
    {
      g_object_unref (worker);
      return NULL;
    }

  return worker;
}

void
g_kdbus_worker_associate (GKDBusWorker                            *worker,
                          GDBusCapabilityFlags                     capabilities,
                          GDBusWorkerMessageReceivedCallback       message_received_callback,
                          GDBusWorkerMessageAboutToBeSentCallback  message_about_to_be_sent_callback,
                          GDBusWorkerDisconnectedCallback          disconnected_callback,
                          gpointer                                 user_data)
{
  worker->capabilities = capabilities;
  worker->message_received_callback = message_received_callback;
  worker->message_about_to_be_sent_callback = message_about_to_be_sent_callback;
  worker->disconnected_callback = disconnected_callback;
  worker->user_data = user_data;
}

void
g_kdbus_worker_unfreeze (GKDBusWorker *worker)
{
  gchar *name;

  if (worker->source != NULL)
    return;

  worker->context = g_main_context_ref_thread_default ();
  worker->source = g_unix_fd_source_new (worker->fd, G_IO_IN);

  g_source_set_callback (worker->source, (GSourceFunc) kdbus_ready, worker, NULL);
  name = g_strdup_printf ("kdbus worker");
  g_source_set_name (worker->source, name);
  g_free (name);

  g_source_attach (worker->source, worker->context);
}

gboolean
g_kdbus_worker_send_message (GKDBusWorker  *worker,
                             GDBusMessage  *message,
                             GError       **error)
{
  return _g_kdbus_send (worker, message, error);
}

void
g_kdbus_worker_stop (GKDBusWorker *worker)
{
}

void
g_kdbus_worker_flush_sync (GKDBusWorker *worker)
{
}

void
g_kdbus_worker_close (GKDBusWorker       *worker,
                      GCancellable       *cancellable,
                      GSimpleAsyncResult *result)
{
}
