/*  GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2013 Samsung Electronics
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
 * Author: Lukasz Skalski       <l.skalski@partner.samsung.com>
 */

#include "config.h"

#include "gkdbus.h"
#include "glib-unix.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdio.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <gio/gio.h>
#include "gcancellable.h"
#include "gioenumtypes.h"
#include "ginitable.h"
#include "gioerror.h"
#include "gioenums.h"
#include "gioerror.h"
#include "glibintl.h"
#include "kdbus.h"
#include "gdbusmessage.h"
#include "gdbusconnection.h"

/* Size of memory registered with Kdbus for receiving messages */
#define KDBUS_POOL_SIZE (16 * 1024 * 1024)
#define KDBUS_BLOOM_SIZE 64

#define ALIGN8(l) (((l) + 7) & ~7)
#define ALIGN8_PTR(p) ((void*) ALIGN8((gulong) p))

#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_ITEM_SIZE(s) ALIGN8((s) + KDBUS_ITEM_HEADER_SIZE)

#define KDBUS_ITEM_NEXT(item) \
        (typeof(item))(((guint8 *)item) + ALIGN8((item)->size))
#define KDBUS_ITEM_FOREACH(item, head, first)                           \
        for (item = (head)->first;                                      \
             (guint8 *)(item) < (guint8 *)(head) + (head)->size;        \
             item = KDBUS_ITEM_NEXT(item))

#define alloca0(n)                                      \
        ({                                              \
                gchar *_new_;                           \
                gssize _len_ = n;                       \
                _new_ = alloca(_len_);                  \
                (void *) memset(_new_, 0, _len_);       \
        })

#define SYSTEMD_BUS_DRIVERD

/**
 * SECTION:gkdbus
 * @short_description: Low-level kdbus object
 * @include: gio/gio.h
 *
 * A #GKdbus is a lowlevel adapter for Kdbus IPC solution. It is meant
 * to replace DBUS  as fundamental IPC solution for  Linux, however it
 * is  still experimental  work in  progress.  You  may  find detailed
 * description in kdbus.txt at https://github.com/gregkh/kdbus
 *
 * Dbus-daemon  use  is  now  limited only  to  administrative  tasks,
 * message routing is done in kernel which is faster.
 *
 * There are two modes of transport - "vectors" and "memfd".
 * Vector   is  standard   and   for  smaller   messages,  less   than
 * MEMFD_SIZE_THRESHOLD.   Memfd is  special case,  designed  for bulk
 * data, with message size over MEMFD_SIZE_THRESHOLD.
 *
 * Some Kdbus  messages e.g. error messages  and Hello msg  need to be
 * converted and passed to  client. For this adaptation reply messages
 * are fabricated locally and inserted into incoming message queue.
 *
 *
 */

static void     g_kdbus_initable_iface_init (GInitableIface  *iface);
static gboolean g_kdbus_initable_init       (GInitable       *initable,
                                             GCancellable    *cancellable,
                                             GError         **error);

G_DEFINE_TYPE_WITH_CODE (GKdbus, g_kdbus, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_kdbus_initable_iface_init));

enum
{
  PROP_0,
  PROP_FD,
  PROP_TIMEOUT,
  PROP_PEER_ID
};


typedef struct {
  GSource        source;
  GPollFD        pollfd;
  GKdbus        *kdbus;
  GIOCondition   condition;
  GCancellable  *cancellable;
  GPollFD        cancel_pollfd;
  gint64         timeout_time;
} GKdbusSource;


struct _GKdbusPrivate
{
  gint              fd;
  gchar             *path;
  gchar             *kdbus_buffer;
  guint64            unique_id;
  guint64            hello_flags;
  guint64            attach_flags;
  guint              registered : 1;
  guint              closed : 1;
  guint              inited : 1;
  guint              timeout;
  guint              timed_out : 1;
  gchar             *msg_buffer_ptr;
  guchar             bus_id[16];
  struct kdbus_msg  *kmsg;
  GString           *msg_sender;
  GString           *msg_destination;
};


/**
 * g_kdbus_get_property:
 *
 */
static void
g_kdbus_get_property (GObject     *object,
                      guint        prop_id,
                      GValue      *value,
                      GParamSpec  *pspec)
{
  GKdbus *kdbus = G_KDBUS (object);

  switch (prop_id)
    {
      case PROP_FD:
        g_value_set_int (value, kdbus->priv->fd);
        break;

      case PROP_TIMEOUT:
        g_value_set_int (value, kdbus->priv->timeout);
        break;

      case PROP_PEER_ID:
        g_value_set_int (value, kdbus->priv->unique_id);
        break;

      default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}


/**
 * g_kdbus_set_property:
 *
 */
static void
g_kdbus_set_property (GObject       *object,
                      guint          prop_id,
                      const GValue  *value,
                      GParamSpec    *pspec)
{
  GKdbus *kdbus = G_KDBUS (object);

  switch (prop_id)
    {
      case PROP_TIMEOUT:
        kdbus->priv->timeout = g_value_get_int (value);
        break;

      default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}


/**
 * g_kdbus_get_last_msg_sender
 *
 */
gchar *
g_kdbus_get_last_msg_sender (GKdbus  *kdbus)
{
  return kdbus->priv->msg_sender->str;
}


/**
 * g_kdbus_get_last_destination
 *
 */
gchar *
g_kdbus_get_last_msg_destination (GKdbus  *kdbus)
{
  return kdbus->priv->msg_destination->str;
}


/**
 * g_kdbus_get_buffer_ptr:
 *
 */
gchar *
g_kdbus_get_msg_buffer_ptr (GKdbus  *kdbus)
{
  return kdbus->priv->msg_buffer_ptr;
}


/**
 * g_kdbus_finalize:
 *
 */
static void
g_kdbus_finalize (GObject  *object)
{
  GKdbus *kdbus = G_KDBUS (object);

  if (kdbus->priv->fd != -1 && !kdbus->priv->closed)
    g_kdbus_try_close (kdbus, NULL);

  g_string_free (kdbus->priv->msg_sender, TRUE);
  g_string_free (kdbus->priv->msg_destination, TRUE);

  if (G_OBJECT_CLASS (g_kdbus_parent_class)->finalize)
    (*G_OBJECT_CLASS (g_kdbus_parent_class)->finalize) (object);

}


/**
 * g_kdbus_class_init:
 *
 */
static void
g_kdbus_class_init (GKdbusClass  *klass)
{
  GObjectClass *gobject_class G_GNUC_UNUSED = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GKdbusPrivate));

  gobject_class->finalize = g_kdbus_finalize;
  gobject_class->set_property = g_kdbus_set_property;
  gobject_class->get_property = g_kdbus_get_property;
}


/**
 * g_kdbus_initable_iface_init:
 *
 */
static void
g_kdbus_initable_iface_init (GInitableIface  *iface)
{
  iface->init = g_kdbus_initable_init;
}


/**
 * g_kdbus_init:
 *
 */
static void
g_kdbus_init (GKdbus  *kdbus)
{
  kdbus->priv = G_TYPE_INSTANCE_GET_PRIVATE (kdbus, G_TYPE_KDBUS, GKdbusPrivate);

  kdbus->priv->fd = -1;
  kdbus->priv->unique_id = -1;
  kdbus->priv->path = NULL;
  kdbus->priv->kdbus_buffer = NULL;

  kdbus->priv->msg_sender = g_string_new (NULL);
  kdbus->priv->msg_destination = g_string_new (NULL);

  kdbus->priv->hello_flags = KDBUS_HELLO_ACCEPT_FD;
  //kdbus->priv->attach_flags = KDBUS_ATTACH_NAMES;
  kdbus->priv->attach_flags = 0;
}


/**
 * g_kdbus_initable_init:
 *
 */
static gboolean
g_kdbus_initable_init (GInitable     *initable,
                       GCancellable  *cancellable,
                       GError       **error)
{
  GKdbus *kdbus;

  g_return_val_if_fail (G_IS_KDBUS (initable), FALSE);

  kdbus = G_KDBUS (initable);

  if (cancellable != NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           _("Cancellable initialization not supported"));
      return FALSE;
    }

  kdbus->priv->inited = TRUE;

  return TRUE;
}


/**
 * kdbus_source_prepare:
 *
 */
static gboolean
kdbus_source_prepare (GSource  *source,
                      gint     *timeout)
{
  GKdbusSource *kdbus_source = (GKdbusSource *)source;

  if (g_cancellable_is_cancelled (kdbus_source->cancellable))
    return TRUE;

  if (kdbus_source->timeout_time)
    {
      gint64 now;

      now = g_source_get_time (source);

      *timeout = (kdbus_source->timeout_time - now + 999) / 1000;
      if (*timeout < 0)
        {
          kdbus_source->kdbus->priv->timed_out = TRUE;
          *timeout = 0;
          return TRUE;
        }
    }
  else
    *timeout = -1;

  if ((kdbus_source->condition & kdbus_source->pollfd.revents) != 0)
    return TRUE;

  return FALSE;
}


/**
 * kdbus_source_check:
 *
 */
static gboolean
kdbus_source_check (GSource  *source)
{
  gint timeout;

  return kdbus_source_prepare (source, &timeout);
}


/**
 * kdbus_source_dispatch
 *
 */
static gboolean
kdbus_source_dispatch  (GSource      *source,
                        GSourceFunc   callback,
                        gpointer      user_data)
{
  GKdbusSourceFunc func = (GKdbusSourceFunc)callback;
  GKdbusSource *kdbus_source = (GKdbusSource *)source;
  GKdbus *kdbus = kdbus_source->kdbus;
  gboolean ret;

  if (kdbus_source->kdbus->priv->timed_out)
    kdbus_source->pollfd.revents |= kdbus_source->condition & (G_IO_IN | G_IO_OUT);

  ret = (*func) (kdbus,
                 kdbus_source->pollfd.revents & kdbus_source->condition,
                 user_data);

  if (kdbus->priv->timeout)
    kdbus_source->timeout_time = g_get_monotonic_time ()
                               + kdbus->priv->timeout * 1000000;

  else
    kdbus_source->timeout_time = 0;

  return ret;
}


/**
 * kdbus_source_finalize
 *
 */
static void
kdbus_source_finalize (GSource  *source)
{
  GKdbusSource *kdbus_source = (GKdbusSource *)source;
  GKdbus *kdbus;

  kdbus = kdbus_source->kdbus;

  g_object_unref (kdbus);

  if (kdbus_source->cancellable)
    {
      g_cancellable_release_fd (kdbus_source->cancellable);
      g_object_unref (kdbus_source->cancellable);
    }
}


/**
 * kdbus_source_closure_callback:
 *
 */
static gboolean
kdbus_source_closure_callback (GKdbus        *kdbus,
                               GIOCondition   condition,
                               gpointer       data)
{
  GClosure *closure = data;
  GValue params[2] = { G_VALUE_INIT, G_VALUE_INIT };
  GValue result_value = G_VALUE_INIT;
  gboolean result;

  g_value_init (&result_value, G_TYPE_BOOLEAN);

  g_value_init (&params[0], G_TYPE_KDBUS);
  g_value_set_object (&params[0], kdbus);
  g_value_init (&params[1], G_TYPE_IO_CONDITION);
  g_value_set_flags (&params[1], condition);

  g_closure_invoke (closure, &result_value, 2, params, NULL);

  result = g_value_get_boolean (&result_value);
  g_value_unset (&result_value);
  g_value_unset (&params[0]);
  g_value_unset (&params[1]);

  return result;
}


static GSourceFuncs kdbus_source_funcs =
{
  kdbus_source_prepare,
  kdbus_source_check,
  kdbus_source_dispatch,
  kdbus_source_finalize,
  (GSourceFunc)kdbus_source_closure_callback,
};


/**
 * kdbus_source_new:
 *
 */
static GSource *
kdbus_source_new (GKdbus        *kdbus,
                  GIOCondition   condition,
                  GCancellable  *cancellable)
{
  GSource *source;
  GKdbusSource *kdbus_source;

  source = g_source_new (&kdbus_source_funcs, sizeof (GKdbusSource));
  g_source_set_name (source, "GKdbus");
  kdbus_source = (GKdbusSource *)source;

  kdbus_source->kdbus = g_object_ref (kdbus);
  kdbus_source->condition = condition;

  if (g_cancellable_make_pollfd (cancellable,
                                 &kdbus_source->cancel_pollfd))
    {
      kdbus_source->cancellable = g_object_ref (cancellable);
      g_source_add_poll (source, &kdbus_source->cancel_pollfd);
    }

  kdbus_source->pollfd.fd = kdbus->priv->fd;
  kdbus_source->pollfd.events = condition;
  kdbus_source->pollfd.revents = 0;
  g_source_add_poll (source, &kdbus_source->pollfd);

  if (kdbus->priv->timeout)
    kdbus_source->timeout_time = g_get_monotonic_time ()
                               + kdbus->priv->timeout * 1000000;
  else
    kdbus_source->timeout_time = 0;

  return source;
}


/**
 * g_kdbus_create_source:
 *
 */
GSource *
g_kdbus_create_source (GKdbus        *kdbus,
                       GIOCondition   condition,
                       GCancellable  *cancellable)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus) && (cancellable == NULL || G_IS_CANCELLABLE (cancellable)), NULL);

  return kdbus_source_new (kdbus, condition, cancellable);
}


/**
 * g_kdbus_open:
 * @kdbus: a #GKdbus.
 * @address: path to kdbus bus file.
 * @error: #GError for error reporting, or %NULL to ignore.
 *
 * Opens file descriptor to kdbus bus control.
 * It is located in /dev/kdbus/uid-name/bus.
 *
 * Returns: TRUE on success.
 */
gboolean
g_kdbus_open (GKdbus       *kdbus,
              const gchar  *address,
              GError      **error)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus), FALSE);

  kdbus->priv->fd = open(address, O_RDWR|O_NOCTTY|O_CLOEXEC);

  if (kdbus->priv->fd<0)
    {
      g_print ("[KDBUS] error when opening endpoint: %m, %d",errno);
      return FALSE;
    }

  kdbus->priv->closed = FALSE;

  return TRUE;
}


/**
 * g_kdbus_try_close:
 * @kdbus: a #GKdbus.
 * @error: #GError for error reporting, or %NULL to ignore.
 *
 * Closes file descriptor to kdbus bus.
 * Disconnect a connection. If the connection's
 * message list is empty, the calls succeeds,
 * closes file descriptor to kdbus bus.
 * Otherwise FALSE is returned without any further
 * side-effects.
 *
 * Returns: TRUE on success.
 *
 */
gboolean
g_kdbus_try_close (GKdbus  *kdbus,
                   GError **error)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus), FALSE);

  if (ioctl(kdbus->priv->fd, KDBUS_CMD_BYEBYE) < 0)
    return FALSE;

  close(kdbus->priv->fd);

  kdbus->priv->closed = TRUE;
  kdbus->priv->registered = FALSE;
  kdbus->priv->fd = -1;

  return TRUE;
}


/**
 * g_kdbus_is_closed:
 * @kdbus: a #GKdbus.
 *
 * checks whether a kdbus is closed.
 *
 */
gboolean
g_kdbus_is_closed (GKdbus  *kdbus)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus), FALSE);

  return kdbus->priv->closed;
}


/**
 * g_kdbus_generate_local_reply:
 * @message: outgoing message from client
 * @message_type: whether is error
 * @message_flags: flags copied
 * @message_body: what to put in reply
 * @error_name: name of error or %NULL
 *
 * Fabricates reply to message.
 *
 */
static GDBusMessage *
g_kdbus_generate_local_reply (GDBusMessage       *message,
                              GDBusMessageType    message_type,
                              GDBusMessageFlags   message_flags,
                              guint32             message_reply_serial,
                              GVariant           *message_body,
                              const gchar        *error_name)
{
  GDBusMessage *reply;

  reply = g_dbus_message_new ();

  g_dbus_message_set_sender (reply, "org.freedesktop.DBus");
  g_dbus_message_set_message_type (reply, message_type);
  g_dbus_message_set_flags (reply, message_flags);
  g_dbus_message_set_reply_serial (reply, message_reply_serial);

  g_dbus_message_set_body (reply, message_body);

  if (message != NULL)
    g_dbus_message_set_destination (reply, g_dbus_message_get_sender (message));

  if (message_type == G_DBUS_MESSAGE_TYPE_ERROR)
    g_dbus_message_set_error_name (reply, error_name);

  if (G_UNLIKELY (_g_dbus_debug_message ()))
    {
      gchar *s;
      _g_dbus_debug_print_lock ();
      g_print ("========================================================================\n"
               "GDBus-debug:Message:\n"
               "  <<<< RECEIVED LOCAL D-Bus message (N/A bytes)\n");

      s = g_dbus_message_print (reply, 2);
      g_print ("%s", s);
      g_free (s);
      _g_dbus_debug_print_unlock ();
    }

  return reply;
}


/**
 * g_kdbus_generate_local_error:
 *
 */
static void
g_kdbus_generate_local_error (GDBusWorker   *worker,
                              GDBusMessage  *dbus_msg,
                              GVariant      *message_body,
                              gint           error_code)
{
  GDBusMessage *reply;
  GError *error = NULL;
  gchar *dbus_error_name;

  error = g_error_new_literal (G_DBUS_ERROR, error_code, "");
  dbus_error_name = g_dbus_error_encode_gerror (error);

  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_ERROR,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        message_body,
                                        dbus_error_name);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);
}


/**
 * g_kdbus_check_signature:
 *
 */
static gboolean
g_kdbus_check_signature (GDBusWorker         *worker,
                         GDBusMessage        *dbus_msg,
                         const gchar         *method_name,
                         GVariant            *body,
                         const GVariantType  *type)
{

  if (!g_variant_is_of_type (body, type))
    {
      GString *error_name = g_string_new (NULL);
      g_string_printf (error_name, "Call to %s has wrong args (expected %s)", method_name, g_variant_type_peek_string (type));
      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_INVALID_ARGS);
      return FALSE;
    }
  else
    return TRUE;
}


/**
 * g_kdbus_check_name:
 *
 */
static gboolean
g_kdbus_check_name (GDBusWorker   *worker,
                    GDBusMessage  *dbus_msg,
                    const gchar   *name)
{
  if (!g_dbus_is_name (name))
    {
      GString *error_name = g_string_new (NULL);
      g_string_printf (error_name, "Name \"%s\" is not valid", name);
      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_INVALID_ARGS);
      return FALSE;
    }
  else
    return TRUE;
}


/**
 * g_kdbus_translate_request_name_flags:
 *
 */
static void
g_kdbus_translate_request_name_flags (GBusNameOwnerFlags   flags,
                                      guint64             *kdbus_flags)
{
  guint64 new_flags = 0;

  if (flags & G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT)
    new_flags |= KDBUS_NAME_ALLOW_REPLACEMENT;

  if (flags & G_BUS_NAME_OWNER_FLAGS_REPLACE)
    new_flags |= KDBUS_NAME_REPLACE_EXISTING;

  *kdbus_flags = new_flags;
}


/**
 * g_kdbus_NameHasOwner:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_NameHasOwner (GKdbus *kdbus, const gchar *name)
{
  struct kdbus_cmd_conn_info *cmd;
  guint64 id;
  gssize size;
  gint ret;

  if (g_dbus_is_unique_name(name))
    {
       size = offsetof(struct kdbus_cmd_conn_info, name);
       cmd = alloca0(size);
       name+=3;
       id = strtol (name,NULL,10);
       cmd->id = id;
    }
  else
    {
       size = offsetof(struct kdbus_cmd_conn_info, name) + strlen(name) + 1;
       cmd = alloca0(size);
       strcpy(cmd->name, name);
    }

  cmd->flags = KDBUS_ATTACH_NAMES;
  cmd->size = size;

  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_CONN_INFO, cmd);

  if (ret<0)
    return FALSE;
  else
    return TRUE;
}


/**
 * g_kdbus_Hello_handler:
 * @kdbus: a #GKdbus.
 *
 * Hello message to get unique name on bus in return
 * Finally mapping memory for incoming messages
 *
 * Returns: TRUE on success.
 *
 */
static gboolean
g_kdbus_Hello_handler (GDBusWorker   *worker,
                       GKdbus        *kdbus,
                       GDBusMessage  *dbus_msg)
{
  struct kdbus_cmd_hello hello;
  GString *unique_name;
  GDBusMessage *reply;

  hello.conn_flags = kdbus->priv->hello_flags;
  hello.attach_flags =  kdbus->priv->attach_flags;
  hello.size = sizeof(hello);
  hello.pool_size = KDBUS_POOL_SIZE;

  if (ioctl(kdbus->priv->fd, KDBUS_CMD_HELLO, &hello))
    g_error("[KDBUS] fd=%d failed to send hello: %m, %d", kdbus->priv->fd,errno);

  kdbus->priv->kdbus_buffer = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, kdbus->priv->fd, 0);

  if (kdbus->priv->kdbus_buffer == MAP_FAILED)
    g_error("[KDBUS] error when mmap: %m, %d", errno);

  if (hello.bus_flags > 0xFFFFFFFFULL || hello.conn_flags > 0xFFFFFFFFULL)
    g_error("[KDBUS] incompatible flags");

  if (hello.bloom_size != KDBUS_BLOOM_SIZE)
    g_error("[KDBUS] diffrent bloom size");

  kdbus->priv->unique_id = hello.id;
  kdbus->priv->registered = TRUE;
  memcpy (kdbus->priv->bus_id, hello.id128, 16);

  unique_name = g_string_new(NULL);
  g_string_printf (unique_name,":1.%" G_GUINT64_FORMAT, kdbus->priv->unique_id);

  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        g_variant_new ("(s)",unique_name->str),
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);

  return TRUE;
}


/**
 * g_kdbus_RequestName_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_RequestName_handler (GDBusWorker   *worker,
                             GKdbus        *kdbus,
                             GDBusMessage  *dbus_msg)
{
  GDBusMessage *reply;
  GBusNameOwnerFlags flags;
  struct kdbus_cmd_name *kdbus_name;
  const gchar *name;
  guint64 kdbus_flags;
  guint64 size;
  gint ret;
  gint status = G_BUS_REQUEST_NAME_REPLY_PRIMARY_OWNER;

  /* read and validate message */
  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "RequestName", body, G_VARIANT_TYPE("(su)")))
      return TRUE;

  g_variant_get (body, "(&su)", &name, &flags);

  if (!g_kdbus_check_name (worker, dbus_msg, name))
      return TRUE;

  if (*name == ':')
    {
      GString *error_name = g_string_new (NULL);
      g_string_printf (error_name, "Cannot acquire a service starting with ':' such as \"%s\"", name);
      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_INVALID_ARGS);
      return TRUE;
    }

  g_kdbus_translate_request_name_flags (flags, &kdbus_flags);

  /* calculate size */
  size = sizeof(*kdbus_name) + strlen(name) + 1;
  kdbus_name = alloca(size);

  /* set message header */
  memset(kdbus_name, 0, size);
  strcpy(kdbus_name->name, name);
  kdbus_name->size = size;
  kdbus_name->flags = kdbus_flags;

  /* send message */
  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_NAME_ACQUIRE, kdbus_name);
  if (ret < 0)
    {
      if (errno == EEXIST)
        status = G_BUS_REQUEST_NAME_REPLY_EXISTS;
      else if (errno == EALREADY)
        status = G_BUS_REQUEST_NAME_REPLY_ALREADY_OWNER;
      else
        return FALSE;
    }

  if (kdbus_name->flags & KDBUS_NAME_IN_QUEUE)
    status = G_BUS_REQUEST_NAME_REPLY_IN_QUEUE;

  /* generate reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        g_variant_new ("(u)",status),
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);

  return TRUE;
}


/**
 * g_kdbus_ReleaseName_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_ReleaseName_handler (GDBusWorker   *worker,
                             GKdbus        *kdbus,
                             GDBusMessage  *dbus_msg)
{
  GDBusMessage *reply;
  struct kdbus_cmd_name *kdbus_name;
  const gchar *name;
  guint64 size;
  gint ret;
  gint status = G_BUS_RELEASE_NAME_REPLY_RELEASED;

  /* read and validate message */
  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "ReleaseName", body, G_VARIANT_TYPE("(s)")))
      return TRUE;

  g_variant_get (body, "(&s)", &name);

  if (!g_kdbus_check_name (worker, dbus_msg, name))
      return TRUE;

  if (*name == ':')
    {
      GString *error_name = g_string_new (NULL);
      g_string_printf (error_name, "Cannot release a service starting with ':' such as \"%s\"", name);
      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_INVALID_ARGS);
      return TRUE;
    }

  /* calculate size */
  size = sizeof(*kdbus_name) + strlen(name) + 1;
  kdbus_name = alloca(size);

  /* set message header */
  memset(kdbus_name, 0, size);
  strcpy(kdbus_name->name, name);
  kdbus_name->size = size;

  /* send message */
  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_NAME_RELEASE, kdbus_name);
  if (ret < 0)
    {
      if (errno == ESRCH)
        status = G_BUS_RELEASE_NAME_REPLY_NON_EXISTENT;
      else if (errno == EADDRINUSE)
        status = G_BUS_RELEASE_NAME_REPLY_NOT_OWNER;
      else
        return FALSE;
    }

  /* generate reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        g_variant_new ("(u)",status),
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);

  return TRUE;
}


/**
 * g_kdbus_ListNames_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_ListNames_handler (GDBusWorker   *worker,
                           GKdbus        *kdbus,
                           GDBusMessage  *dbus_msg,
                           guint64        flags)
{
  GDBusMessage *reply;
  GVariantBuilder *builder;
  struct kdbus_cmd_name_list cmd = {};
  struct kdbus_name_list *name_list;
  struct kdbus_cmd_name *name;
  guint64 prev_id = 0;
  gint ret;

  cmd.flags = flags;

  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_NAME_LIST, &cmd);
  if (ret < 0)
    return FALSE;

  /* get name list */
  name_list = (struct kdbus_name_list *) ((guint8 *) kdbus->priv->kdbus_buffer + cmd.offset);

  builder = g_variant_builder_new (G_VARIANT_TYPE ("as"));
  KDBUS_ITEM_FOREACH(name, name_list, names)
    {
      if ((flags & KDBUS_NAME_LIST_UNIQUE) && name->owner_id != prev_id)
        {
          gchar *unique_name;

          if (asprintf(&unique_name, ":1.%llu", (unsigned long long) name->owner_id) < 0)
            return FALSE;

          g_variant_builder_add (builder, "s", unique_name);
          prev_id = name->owner_id;
        }

        if (g_dbus_is_name (name->name))
          g_variant_builder_add (builder, "s", name->name);
    }

  /* generate reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        g_variant_new ("(as)", builder),
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);

  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_FREE, &cmd.offset);
  if (ret < 0)
    return FALSE;

  return TRUE;
}


/**
 * g_kdbus_ListQueuedOwners_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_ListQueuedOwners_handler (GDBusWorker   *worker,
                                  GKdbus        *kdbus,
                                  GDBusMessage  *dbus_msg)
{
  GDBusMessage *reply;
  GVariantBuilder *builder;
  struct kdbus_cmd_name_list cmd = {};
  struct kdbus_name_list *name_list;
  struct kdbus_cmd_name *name;
  const gchar *service;
  gint ret;

  /* read and validate message */
  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "ListQueuedOwners", body, G_VARIANT_TYPE("(s)")))
      return TRUE;

  g_variant_get (body, "(&s)", &service);

  if (!g_kdbus_check_name (worker, dbus_msg, service))
      return TRUE;

  if (!g_kdbus_NameHasOwner (kdbus, service))
    {
      GString *error_name = g_string_new (NULL);
      g_string_printf (error_name, "Could not get owners of name \'%s\': no such name", service);
      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_NAME_HAS_NO_OWNER);
      return TRUE;
    }

  /* get queued name list */
  cmd.flags = KDBUS_NAME_LIST_QUEUED;

  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_NAME_LIST, &cmd);
  if (ret < 0)
    return FALSE;

  name_list = (struct kdbus_name_list *) ((guint8 *) kdbus->priv->kdbus_buffer + cmd.offset);

  builder = g_variant_builder_new (G_VARIANT_TYPE ("as"));
  KDBUS_ITEM_FOREACH(name, name_list, names)
    {
      gchar *unique_name;

      if (name->size <= sizeof(*name))
        continue;

      if (strcmp(name->name, service))
        continue;

      if (asprintf(&unique_name, ":1.%llu", (unsigned long long) name->owner_id) < 0)
        return FALSE;

      g_variant_builder_add (builder, "s", unique_name);

    }

  /* generate reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        g_variant_new ("(as)", builder),
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);

  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_FREE, &cmd.offset);
  if (ret < 0)
    return FALSE;

  return TRUE;
}


/**
 * g_kdbus_GetOwner_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_GetOwner_handler (GDBusWorker   *worker,
                          GKdbus        *kdbus,
                          GDBusMessage  *dbus_msg,
                          guint64        flag)
{
  GVariant *result = NULL;
  GDBusMessage *reply;
  struct kdbus_cmd_conn_info *cmd;
  struct kdbus_conn_info *conn_info;
  struct kdbus_item *item;
  const gchar *name;
  guint64 id;
  gssize size;
  gint ret;

  /* read and validate message */
  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "GetOwner", body, G_VARIANT_TYPE("(s)")))
      return TRUE;

  g_variant_get (body, "(&s)", &name);

  if (!g_kdbus_check_name (worker, dbus_msg, name))
      return TRUE;

  /* setup kmsg for ioctl */
  if (g_dbus_is_unique_name(name))
    {
       size = offsetof(struct kdbus_cmd_conn_info, name);
       cmd = alloca0(size);
       name+=3;
       id = strtol (name,NULL,10);
       cmd->id = id;
    }
  else
    {
       size = offsetof(struct kdbus_cmd_conn_info, name) + strlen(name) + 1;
       cmd = alloca0(size);
       strcpy(cmd->name, name);
    }

  cmd->flags = KDBUS_ATTACH_NAMES;
  cmd->size = size;

  /* get info about connection */
  ret = ioctl(kdbus->priv->fd, KDBUS_CMD_CONN_INFO, cmd);
  if (ret < 0)
    {
      GString *error_name = g_string_new (NULL);
      g_string_printf (error_name, "Could not get owners of name \'%s\': no such name", name);
      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_NAME_HAS_NO_OWNER);
      return TRUE;
    }

  conn_info = (struct kdbus_conn_info *) ((guint8 *) kdbus->priv->kdbus_buffer + cmd->offset);

  if (conn_info->flags & KDBUS_HELLO_ACTIVATOR)
    return FALSE;

  if (flag == G_BUS_CREDS_UNIQUE_NAME)
    {
       gchar *unique_name;
       if (asprintf(&unique_name, ":1.%llu", (unsigned long long) conn_info->id) < 0)
         return FALSE;

         result = g_variant_new ("(s)", unique_name);
         goto send_reply;
    }

  /* read creds info's */
  KDBUS_ITEM_FOREACH(item, conn_info, items)
   {

      switch (item->type)
        {

          case KDBUS_ITEM_CREDS:

            if (flag == G_BUS_CREDS_PID)
              {
                guint pid = item->creds.pid;
                result = g_variant_new ("(u)", pid);
                goto send_reply;
              }

            if (flag == G_BUS_CREDS_UID)
              {
                guint uid = item->creds.uid;
                result = g_variant_new ("(u)", uid);
                goto send_reply;
              }

          case KDBUS_ITEM_SECLABEL:
            if (flag == G_BUS_CREDS_SELINUX_CONTEXT)
              {
                gint counter;
                gchar *label = NULL;
                GVariantBuilder *builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));

                label = strdup(item->str);
                if (!label)
                  goto exit;

                for (counter = 0 ; counter < strlen (label) ; counter++)
                  {
                    g_variant_builder_add (builder, "y", label);
                    label++;
                  }

                result = g_variant_new ("(ay)", builder);
                goto send_reply;

              }
            break;

          case KDBUS_ITEM_PID_COMM:
          case KDBUS_ITEM_TID_COMM:
          case KDBUS_ITEM_EXE:
          case KDBUS_ITEM_CMDLINE:
          case KDBUS_ITEM_CGROUP:
          case KDBUS_ITEM_CAPS:
          case KDBUS_ITEM_NAME:
          case KDBUS_ITEM_AUDIT:
            break;

        }
   }

send_reply:
  if (result == NULL)
    goto exit;

  /* generate reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        result,
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);

exit:
  ioctl(kdbus->priv->fd, KDBUS_CMD_FREE, &cmd->offset);
  return TRUE;

}


/**
 * g_kdbus_NameHasOwner_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_NameHasOwner_handler (GDBusWorker   *worker,
                              GKdbus        *kdbus,
                              GDBusMessage  *dbus_msg)
{
  GDBusMessage *reply;
  GVariant *result = NULL;
  const gchar *name;

  /* read and validate message */
  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "NameHasOwner", body, G_VARIANT_TYPE("(s)")))
      return TRUE;

  g_variant_get (body, "(&s)", &name);

  if (!g_kdbus_check_name (worker, dbus_msg, name))
      return TRUE;

  /* check whether name has owner */
  if (!g_kdbus_NameHasOwner (kdbus, name))
    result = g_variant_new ("(b)", FALSE);
  else
    result = g_variant_new ("(b)", TRUE);

  /* generate reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        result,
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);
  return TRUE;
}


/**
 * g_kdbus_GetId_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_GetId_handler (GDBusWorker   *worker,
                       GKdbus        *kdbus,
                       GDBusMessage  *dbus_msg)
{
  GDBusMessage *reply;
  GString *result = g_string_new (NULL);
  gint i;

  for (i=0; i<16; i++)
    g_string_append_printf (result, "%02x", kdbus->priv->bus_id[i]);

  /* generate local reply */
  reply = g_kdbus_generate_local_reply (dbus_msg,
                                        G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        g_dbus_message_get_serial (dbus_msg),
                                        g_variant_new ("(s)", result->str),
                                        NULL);
  _g_dbus_worker_queue_or_deliver_received_message (worker, reply);
  return TRUE;
}


/**
 * g_kdbus_StartServiceByName_handler:
 * Returns: TRUE on success.
 * TODO
 */
static gboolean
g_kdbus_StartServiceByName_handler (GDBusWorker   *worker,
                                    GKdbus        *kdbus,
                                    GDBusMessage  *dbus_msg)
{
  GDBusMessage *reply;
  GVariant *body;
  const gchar *name;
  guint64 flags;

  body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "StartServiceByName", body, G_VARIANT_TYPE("(su)")))
      return TRUE;

  g_variant_get (body, "(&su)", &name, &flags);

  if (!g_kdbus_check_name (worker, dbus_msg, name))
      return TRUE;

  if (g_kdbus_NameHasOwner (kdbus, name))
    {
      reply = g_kdbus_generate_local_reply (dbus_msg,
                                            G_DBUS_MESSAGE_TYPE_METHOD_RETURN,
                                            G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                            g_dbus_message_get_serial (dbus_msg),
                                            g_variant_new ("(u)", G_BUS_START_REPLY_ALREADY_RUNNING),
                                            NULL);
      _g_dbus_worker_queue_or_deliver_received_message (worker, reply);
      return TRUE;
    }

  /* TODO */
  g_error ("[KDBUS] StartServiceByName method is not implemented yet");

  return TRUE;
}


/**
 * g_kdbus_AddMatch_handler:
 * Returns: TRUE on success.
 * TODO
 */
static gboolean
g_kdbus_AddMatch_handler (GDBusWorker   *worker,
                          GKdbus        *kdbus,
                          GDBusMessage  *dbus_msg)
{
/*
  const gchar *rule;

  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "AddMatch", body, G_VARIANT_TYPE("(s)")))
      return TRUE;

  g_variant_get (body, "(&s)", &rule);
*/

  /* TODO */
  g_error ("[KDBUS] AddMatch method is not implemented yet");

  return TRUE;
}


/**
 * g_kdbus_RemoveMatch_handler:
 * Returns: TRUE on success.
 * TODO
 */
static gboolean
g_kdbus_RemoveMatch_handler (GDBusWorker   *worker,
                             GKdbus        *kdbus,
                             GDBusMessage  *dbus_msg)
{
/*
  const gchar *rule;

  GVariant *body = g_dbus_message_get_body (dbus_msg);

  if (!g_kdbus_check_signature (worker, dbus_msg, "RemoveMatch", body, G_VARIANT_TYPE("(s)")))
      return TRUE;

  g_variant_get (body, "(&s)", &rule);
*/

  /* TODO */
  g_error ("[KDBUS] RemoveMatch method is not implemented yet");

  return TRUE;
}


/**
 * g_kdbus_UnsupportedMethod_handler:
 * Returns: TRUE on success.
 */
static gboolean
g_kdbus_UnsupportedMethod_handler (GDBusWorker   *worker,
                                   GKdbus        *kdbus,
                                   GDBusMessage  *dbus_msg,
                                   const gchar   *method_name)
{
  GString *error_name = g_string_new (NULL);
  g_string_printf (error_name, "Method \"%s\" is not supported", method_name);
  g_kdbus_generate_local_error (worker,
                                dbus_msg,
                                g_variant_new ("(s)",error_name->str),
                                G_DBUS_ERROR_UNKNOWN_METHOD);
  return TRUE;
}


/**
 * g_kdbus_bus_driver:
 *
 */
static gboolean
g_kdbus_bus_driver (GDBusWorker   *worker,
                    GKdbus        *kdbus,
                    GDBusMessage  *dbus_msg)
{
  gboolean ret = FALSE;

  /* RequestName and ReleaseName */
  if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "RequestName") == 0)
    ret = g_kdbus_RequestName_handler (worker, kdbus, dbus_msg);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "ReleaseName") == 0)
    ret = g_kdbus_ReleaseName_handler (worker, kdbus, dbus_msg);

  /* All List* Methods */
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "ListNames") == 0)
    ret = g_kdbus_ListNames_handler (worker, kdbus, dbus_msg, KDBUS_NAME_LIST_UNIQUE | KDBUS_NAME_LIST_NAMES);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "ListActivatableNames") == 0)
    ret = g_kdbus_ListNames_handler (worker, kdbus, dbus_msg, KDBUS_NAME_LIST_ACTIVATORS);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "ListQueuedOwners") == 0)
    ret = g_kdbus_ListQueuedOwners_handler (worker, kdbus, dbus_msg);

  /* All Get* Methods */
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "GetNameOwner") == 0)
    ret = g_kdbus_GetOwner_handler (worker, kdbus, dbus_msg, G_BUS_CREDS_UNIQUE_NAME);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "GetConnectionUnixProcessID") == 0)
    ret = g_kdbus_GetOwner_handler (worker, kdbus, dbus_msg, G_BUS_CREDS_PID);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "GetConnectionUnixUser") == 0)
    ret = g_kdbus_GetOwner_handler (worker, kdbus, dbus_msg, G_BUS_CREDS_UID);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "GetConnectionSELinuxSecurityContext") == 0)
    ret = g_kdbus_GetOwner_handler (worker, kdbus, dbus_msg, G_BUS_CREDS_SELINUX_CONTEXT);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "GetId") == 0)
    ret = g_kdbus_GetId_handler (worker, kdbus, dbus_msg);

  /* NameHasOwner nad StartServiceByName methods */
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "NameHasOwner") == 0)
    ret = g_kdbus_NameHasOwner_handler (worker, kdbus, dbus_msg);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "StartServiceByName") == 0)
    ret = g_kdbus_StartServiceByName_handler (worker, kdbus, dbus_msg);

  /* AddMatch and RemoveMatch */
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "AddMatch") == 0)
    ret = g_kdbus_AddMatch_handler (worker, kdbus, dbus_msg);
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "RemoveMatch") == 0)
    ret = g_kdbus_RemoveMatch_handler (worker, kdbus, dbus_msg);

  /* Unsupported Methods */
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "ReloadConfig") == 0)
    ret = g_kdbus_UnsupportedMethod_handler (worker, kdbus, dbus_msg, "ReloadConfig");
  else if (g_strcmp0(g_dbus_message_get_member(dbus_msg), "UpdateActivationEnvironment") == 0)
    ret = g_kdbus_UnsupportedMethod_handler (worker, kdbus, dbus_msg, "UpdateActivationEnvironment");

  else
    {
      GString *error_name;

      error_name = g_string_new (NULL);
      g_string_printf (error_name, "org.freedesktop.DBus does not understand message %s", g_dbus_message_get_member(dbus_msg));

      g_kdbus_generate_local_error (worker,
                                    dbus_msg,
                                    g_variant_new ("(s)",error_name->str),
                                    G_DBUS_ERROR_UNKNOWN_METHOD);
    }

  return ret;
}


/**
 * g_kdbus_release_msg:
 * Release memory occupied by kdbus_msg.
 * Use after DBUS message is extracted.
 */
void
g_kdbus_release_kmsg (GKdbus  *kdbus)
{
  guint64 offset;

  offset = (guint8 *)kdbus->priv->kmsg - (guint8 *)kdbus->priv->kdbus_buffer;
  ioctl(kdbus->priv->fd, KDBUS_CMD_FREE, &offset);

  /* TODO: Add here closing FDS and MEMFD after adding support for them */
}


/**
 * g_kdbus_append_payload_vec:
 *
 */
static void
g_kdbus_append_payload_vec (struct kdbus_item **item,
                            const void         *data_ptr,
                            gssize              size)
{
        *item = ALIGN8_PTR(*item);
        (*item)->size = offsetof(struct kdbus_item, vec) + sizeof(struct kdbus_vec);
        (*item)->type = KDBUS_ITEM_PAYLOAD_VEC;
        (*item)->vec.address = (guint64)((guintptr)data_ptr);
        (*item)->vec.size = size;
        *item = KDBUS_ITEM_NEXT(*item);
}


/**
 * g_kdbus_append_payload_destiantion:
 *
 */
static void
g_kdbus_append_destination (struct kdbus_item **item,
                            const gchar        *destination,
                            gssize              size)
{
        *item = ALIGN8_PTR(*item);
        (*item)->size = offsetof(struct kdbus_item, str) + size + 1;
        (*item)->type = KDBUS_ITEM_DST_NAME;
        memcpy ((*item)->str, destination, size+1);
        *item = KDBUS_ITEM_NEXT(*item);
}


/**
 * g_kdbus_append_payload_bloom:
 *
 */
static void
g_kdbus_append_bloom (struct kdbus_item **item,
                      gssize              size)
{
        *item = ALIGN8_PTR(*item);
        (*item)->size = offsetof(struct kdbus_item, data) + size;
        (*item)->type = KDBUS_ITEM_BLOOM;
        *item = KDBUS_ITEM_NEXT(*item);
}


/**
 * g_kdbus_NameOwnerChanged_generate:
 * TODO: Not tesed yet
 */
static gsize
g_kdbus_NameOwnerChanged_generate (GKdbus             *kdbus,
                                   struct kdbus_item  *item)
{
  GVariant *result = NULL;
  GDBusMessage *reply;
  GError *error;
  guchar *blob;
  gsize reply_size;

  gchar *owner;
  gchar *old_owner;
  gchar *new_owner;

  /* ID change */
  if (item->type == KDBUS_ITEM_ID_ADD || item->type == KDBUS_ITEM_ID_REMOVE)
    {
      owner = "";

      if (item->type == KDBUS_ITEM_ID_ADD)
        {
          old_owner = NULL;
          new_owner = owner;
        }
      else
        {
          old_owner = owner;
          new_owner = NULL;
        }
    }

  /* name change */
  if (item->type == KDBUS_ITEM_NAME_ADD ||
      item->type == KDBUS_ITEM_NAME_REMOVE ||
      item->type == KDBUS_ITEM_NAME_CHANGE )
    {
     g_error ("[KDBUS] 'NameChange' is not implemented yet");
    }

  result = g_variant_new ("(sss)", owner, old_owner, new_owner);
  reply = g_kdbus_generate_local_reply (NULL,
                                        G_DBUS_MESSAGE_TYPE_SIGNAL,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        -1,
                                        result,
                                        NULL);

  blob =  g_dbus_message_to_blob (reply, &reply_size, 0, &error);
  if (blob == NULL)
    g_error ("[KDBUS] BLOB == NULL: %s\n",error->message);

  ((guint32 *) blob)[2] = GUINT32_TO_LE (-1);
  kdbus->priv->msg_buffer_ptr = (gchar *)blob;

  return reply_size;

}


/**
 * g_kdbus_KernelMethodError_generate:
 * TODO: Test it after fix TIMEOUT bug in kdbus code
 */
static gsize
g_kdbus_KernelMethodError_generate (GKdbus             *kdbus,
                                    struct kdbus_item  *item)
{
  GVariant *error_name;
  GDBusMessage *reply;
  GError *error;
  guchar *blob;
  gsize reply_size;

  if (item->type == KDBUS_ITEM_REPLY_TIMEOUT)
    error_name = g_variant_new ("(s)", "Method call timed out");
  else
    error_name = g_variant_new ("(s)", "Method call peer died");

  error = NULL;
  reply = g_kdbus_generate_local_reply (NULL,
                                        G_DBUS_MESSAGE_TYPE_ERROR,
                                        G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED,
                                        -1,
                                        error_name,
                                        "org.freedesktop.DBus.Error.NoReply");

  blob =  g_dbus_message_to_blob (reply, &reply_size, 0, &error);
  if (blob == NULL)
    g_error ("[KDBUS] BLOB == NULL: %s\n",error->message);

  ((guint32 *) blob)[2] = GUINT32_TO_LE (-1);
  kdbus->priv->msg_buffer_ptr = (gchar *)blob;

  return reply_size;
}


/**
 * g_kdbus_decode_kernel_msg:
 * TODO: Not tested yet
 */
static gsize
g_kdbus_decode_kernel_msg (GKdbus  *kdbus)
{
  struct kdbus_item *item = NULL;
  gsize size = -1;
  g_print ("PID %d dostal wiadomosc od kernela\n",getpid());
  KDBUS_ITEM_FOREACH(item, kdbus->priv->kmsg, items)
    {
      switch (item->type)
        {
          case KDBUS_ITEM_ID_ADD:
          case KDBUS_ITEM_ID_REMOVE:
          case KDBUS_ITEM_NAME_ADD:
          case KDBUS_ITEM_NAME_REMOVE:
          case KDBUS_ITEM_NAME_CHANGE:
            size = g_kdbus_NameOwnerChanged_generate (kdbus, item);
            break;

          case KDBUS_ITEM_REPLY_TIMEOUT:
          case KDBUS_ITEM_REPLY_DEAD:
            size = g_kdbus_KernelMethodError_generate (kdbus, item);
            break;

          default:

            g_error ("[KDBUS] Got unknown field from kernel");
            break;
        }
    }

  /* Override information from the user header with data from the kernel */
  g_string_printf (kdbus->priv->msg_sender, "org.freedesktop.DBus");

  /* for destination */
  if (kdbus->priv->kmsg->dst_id == KDBUS_DST_ID_BROADCAST)
    /* for broadcast messages we don't have to set destination */
    ;
  else if (kdbus->priv->kmsg->dst_id == KDBUS_DST_ID_NAME)
    g_string_printf (kdbus->priv->msg_destination, ":1.%" G_GUINT64_FORMAT, (guint64) kdbus->priv->unique_id);
  else
    g_string_printf (kdbus->priv->msg_destination, ":1.%" G_GUINT64_FORMAT, (guint64) kdbus->priv->kmsg->dst_id);


  return size;
}


/**
 * g_kdbus_decode_dbus_msg:
 *
 */
static gsize
g_kdbus_decode_dbus_msg (GKdbus  *kdbus)
{
  const struct kdbus_item *item;
  gint ret_size = 0;
  const gchar *destination = NULL;
  static gboolean lock = FALSE;

  KDBUS_ITEM_FOREACH(item, kdbus->priv->kmsg, items)
    {
      if (item->size <= KDBUS_ITEM_HEADER_SIZE)
        {
          g_error("[KDBUS] %llu bytes - invalid data record\n", item->size);
          break;
        }

      switch (item->type)
        {

         /* KDBUS_ITEM_DST_NAME */
         case KDBUS_ITEM_DST_NAME:
           destination = item->str;
           break;

        /* KDBUS_ITEM_PALOAD_OFF */
        case KDBUS_ITEM_PAYLOAD_OFF:

          if (!lock)
            {
              kdbus->priv->msg_buffer_ptr = kdbus->priv->kdbus_buffer + item->vec.offset;
              lock=TRUE;
            }
          ret_size += item->vec.size;

          break;

        /* KDBUS_ITEM_* */
        case KDBUS_ITEM_PAYLOAD_MEMFD:
        case KDBUS_ITEM_CREDS:
        case KDBUS_ITEM_TIMESTAMP:
        case KDBUS_ITEM_PID_COMM:
        case KDBUS_ITEM_TID_COMM:
        case KDBUS_ITEM_EXE:
        case KDBUS_ITEM_CMDLINE:
        case KDBUS_ITEM_CGROUP:
        case KDBUS_ITEM_AUDIT:
        case KDBUS_ITEM_CAPS:
        case KDBUS_ITEM_NAME:
        case KDBUS_ITEM_FDS:
        case KDBUS_ITEM_SECLABEL:
          g_print ("[KDBUS] ITEM  %lld is not supported yet\n", item->type);
          break;

        default:
          g_error ("[KDBUS] Unknown filed from kernel - %lld", item->type);
          break;
        }
    }

  /* Override information from the user header with data from the kernel */

  /* for sender */
  if (kdbus->priv->kmsg->src_id == KDBUS_SRC_ID_KERNEL)
    g_string_printf (kdbus->priv->msg_sender, "org.freedesktop.DBus");
  else
    g_string_printf (kdbus->priv->msg_sender, ":1.%" G_GUINT64_FORMAT, (guint64) kdbus->priv->kmsg->src_id);

  /* for destination */
  if (destination)
    g_string_printf (kdbus->priv->msg_destination, "%s", destination);
  else if (kdbus->priv->kmsg->dst_id == KDBUS_DST_ID_BROADCAST)
    /* for broadcast messages we don't have to set destination */
    ;
  else if (kdbus->priv->kmsg->dst_id == KDBUS_DST_ID_NAME)
    g_string_printf (kdbus->priv->msg_destination, ":1.%" G_GUINT64_FORMAT, (guint64) kdbus->priv->unique_id);
  else
    g_string_printf (kdbus->priv->msg_destination, ":1.%" G_GUINT64_FORMAT, (guint64) kdbus->priv->kmsg->dst_id);

  lock = FALSE;
  return ret_size;
}


/**
 * g_kdbus_receive:
 *
 */
gsize
g_kdbus_receive (GKdbus        *kdbus,
                 GCancellable  *cancellable,
                 GError       **error)
{
  guint64 offset;
  gsize size;

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return -1;

  again:
    if (ioctl(kdbus->priv->fd, KDBUS_CMD_MSG_RECV, &offset) < 0)
      {
        if (errno == EINTR)
          goto again;

        g_print ("[KDBUS] ioctl MSG_RECV failed! %d (%m)\n",errno);
        g_set_error (error, G_IO_ERROR, g_io_error_from_errno(errno),_("Error receiving message - KDBUS_CMD_MSG_RECV error"));
        return -1;
      }

    kdbus->priv->kmsg = (struct kdbus_msg *)((guint8 *)kdbus->priv->kdbus_buffer + offset);

    if (kdbus->priv->kmsg->payload_type == KDBUS_PAYLOAD_DBUS)
        size = g_kdbus_decode_dbus_msg (kdbus);
    else if (kdbus->priv->kmsg->payload_type == KDBUS_PAYLOAD_KERNEL)
        size = g_kdbus_decode_kernel_msg (kdbus);
    else
        size = -1;

    return size;
}


/**
 * g_kdbus_send_message:
 * Returns: size of data sent or -1 when error
 */
gsize
g_kdbus_send (GDBusWorker   *worker,
              GKdbus        *kdbus,
              GDBusMessage  *dbus_msg,
              gchar         *blob,
              gsize          blob_size,
              GCancellable  *cancellable,
              GError       **error)
{

  struct kdbus_msg* kmsg;
  struct kdbus_item *item;
  guint64 kmsg_size = 0;
  const gchar *name;
  guint64 dst_id = KDBUS_DST_ID_BROADCAST;

  g_return_val_if_fail (G_IS_KDBUS (kdbus), -1);

  if (g_cancellable_set_error_if_cancelled (cancellable, error))
    return -1;

  /* handle 'Hello' method */
  if ((g_strcmp0(g_dbus_message_get_destination(dbus_msg), "org.freedesktop.DBus") == 0) &&
      (g_strcmp0(g_dbus_message_get_member(dbus_msg), "Hello") == 0))
    {
      if (g_kdbus_Hello_handler (worker, kdbus, dbus_msg))
        return blob_size;
      else
        return -1;
    }

#ifndef SYSTEMD_BUS_DRIVERD
  /* If systemd-bus-driverd from systemd isn't available
     try to process the bus driver messages locally */
  if (g_strcmp0(g_dbus_message_get_destination(dbus_msg), "org.freedesktop.DBus") == 0)
    {
      if (g_kdbus_bus_driver (worker, kdbus, dbus_msg))
        return blob_size;
      else
        return -1;
    }
#endif

  /* check destination */
  if ((name = g_dbus_message_get_destination(dbus_msg)))
    {
      dst_id = KDBUS_DST_ID_NAME;
      if ((name[0] == ':') && (name[1] == '1') && (name[2] == '.'))
        {
          dst_id = strtoull(&name[3], NULL, 10);
          name=NULL;
        }
    }

  /* check kernel message size */
  kmsg_size = sizeof(struct kdbus_msg);
  kmsg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

  if (name)
    kmsg_size += KDBUS_ITEM_SIZE(strlen(name) + 1);
  else if (dst_id == KDBUS_DST_ID_BROADCAST)
    kmsg_size += KDBUS_ITEM_HEADER_SIZE + KDBUS_BLOOM_SIZE;

  kmsg = malloc(kmsg_size);
  if (!kmsg)
    g_error ("[KDBUS] kmsg malloc error");

  /* set message header */
  memset(kmsg, 0, kmsg_size);
  kmsg->size = kmsg_size;
  kmsg->payload_type = KDBUS_PAYLOAD_DBUS;
  kmsg->dst_id = name ? 0 : dst_id;
  kmsg->src_id = kdbus->priv->unique_id;
  kmsg->cookie = g_dbus_message_get_serial(dbus_msg);

  kmsg->flags = ((g_dbus_message_get_flags (dbus_msg) & G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED) ? 0 : KDBUS_MSG_FLAGS_EXPECT_REPLY) |
                ((g_dbus_message_get_flags (dbus_msg) & G_DBUS_MESSAGE_FLAGS_NO_AUTO_START) ? KDBUS_MSG_FLAGS_NO_AUTO_START : 0);

  if ((kmsg->flags) & KDBUS_MSG_FLAGS_EXPECT_REPLY)
    kmsg->timeout_ns = 5000000;
  else
    kmsg->cookie_reply = g_dbus_message_get_reply_serial(dbus_msg);

  /* append payload */
  item = kmsg->items;
  g_kdbus_append_payload_vec (&item, blob, blob_size);

  /* append destination */
  if (name)
    g_kdbus_append_destination (&item, name, strlen(name));
  else if (dst_id == KDBUS_DST_ID_BROADCAST)
    g_kdbus_append_bloom (&item, KDBUS_BLOOM_SIZE);

again:
  if (ioctl(kdbus->priv->fd, KDBUS_CMD_MSG_SEND, kmsg))
    {
      GString *error_name;

      error_name = g_string_new (NULL);

      if(errno == EINTR)
        goto again;
      else if (errno == ENXIO)
        {
          g_string_printf (error_name, "Name %s does not exist", g_dbus_message_get_destination(dbus_msg));
          g_kdbus_generate_local_error (worker,
                                        dbus_msg,
                                        g_variant_new ("(s)",error_name->str),
                                        G_DBUS_ERROR_SERVICE_UNKNOWN);
          return 0;
        }
      else if ((errno == ESRCH) || (errno == EADDRNOTAVAIL))
        {
          if (kmsg->flags & KDBUS_MSG_FLAGS_NO_AUTO_START)
            {
              g_string_printf (error_name, "Name %s does not exist", g_dbus_message_get_destination(dbus_msg));
              g_kdbus_generate_local_error (worker,
                                            dbus_msg,
                                            g_variant_new ("(s)",error_name->str),
                                            G_DBUS_ERROR_SERVICE_UNKNOWN);
              return 0;
            }
          else
            {
              g_string_printf (error_name, "The name %s was not provided by any .service files", g_dbus_message_get_destination(dbus_msg));
              g_kdbus_generate_local_error (worker,
                                            dbus_msg,
                                            g_variant_new ("(s)",error_name->str),
                                            G_DBUS_ERROR_SERVICE_UNKNOWN);
              return 0;
            }
        }

      g_print ("[KDBUS] ioctl error sending kdbus message:%d (%m)\n",errno);
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno(errno), _("Error sending message - KDBUS_CMD_MSG_SEND error"));
      return -1;
    }
  free(kmsg);
  return blob_size;
}
