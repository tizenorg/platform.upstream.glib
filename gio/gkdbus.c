/*  GIO - GLib Input, Output and Streaming Library
 *
 * Copyright © 2013 Samsung
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
 * Authors: Michal Eljasiewicz <m.eljasiewic@samsung.com>
 * Authors: Lukasz Skalski <l.skalski@partner.samsung.com>
 */

#include "config.h"

#include "gkdbus.h"
#include "glib-unix.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

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

#define KDBUS_PART_FOREACH(part, head, first)				\
	for (part = (head)->first;					\
	     (guint8 *)(part) < (guint8 *)(head) + (head)->size;	\
	     part = KDBUS_PART_NEXT(part))
#define RECEIVE_POOL_SIZE (10 * 1024LU * 1024LU)

#define MSG_ITEM_BUILD_VEC(data, datasize)                                    \
	item->type = KDBUS_MSG_PAYLOAD_VEC;					\
        item->size = KDBUS_PART_HEADER_SIZE + sizeof(struct kdbus_vec);		\
        item->vec.address = (unsigned long) data;       			\
        item->vec.size = datasize;

#define KDBUS_ALIGN8(l) (((l) + 7) & ~7)
#define KDBUS_PART_NEXT(part) \
	(typeof(part))(((guint8 *)part) + KDBUS_ALIGN8((part)->size))
#define KDBUS_ITEM_SIZE(s) KDBUS_ALIGN8((s) + KDBUS_PART_HEADER_SIZE)

/**
 * SECTION:gkdbus
 * @short_description: Low-level kdbus object
 * @include: gio/gio.h
 * @see_also: #GInitable, <link linkend="gio-gnetworking.h">gnetworking.h</link>
 *
 */

static void     g_kdbus_initable_iface_init (GInitableIface  *iface);
static gboolean g_kdbus_initable_init       (GInitable       *initable,
					      GCancellable    *cancellable,
					      GError         **error);

G_DEFINE_TYPE_WITH_CODE (GKdbus, g_kdbus, G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
						g_kdbus_initable_iface_init));

struct _GKdbusPrivate
{
  gchar          *path;
  gint            fd;
  guint           closed : 1;
  guint           inited : 1;
  gchar          *buffer_ptr;
};

// TODO:
static void
g_kdbus_get_property (GObject    *object,
		       guint       prop_id,
		       GValue     *value,
		       GParamSpec *pspec)
{
  //GKdbus *kdbus = G_KDBUS (object);

  switch (prop_id)
    {
      default:
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

// TODO:
static void
g_kdbus_set_property (GObject      *object,
		       guint         prop_id,
		       const GValue *value,
		       GParamSpec   *pspec)
{
  //GKdbus *kdbus = G_KDBUS (object);

  switch (prop_id)
    {
      default:
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

// TODO:
static void
g_kdbus_finalize (GObject *object)
{
  //GKdbus *kdbus = G_KDBUS (object);

  // TODO: Posprzatac po obiekcie

}

static void
g_kdbus_class_init (GKdbusClass *klass)
{
  GObjectClass *gobject_class G_GNUC_UNUSED = G_OBJECT_CLASS (klass);

  g_type_class_add_private (klass, sizeof (GKdbusPrivate));

  gobject_class->finalize = g_kdbus_finalize;
  gobject_class->set_property = g_kdbus_set_property;
  gobject_class->get_property = g_kdbus_get_property;
}

static void
g_kdbus_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_kdbus_initable_init;
}

static void
g_kdbus_init (GKdbus *kdbus)
{
  kdbus->priv = G_TYPE_INSTANCE_GET_PRIVATE (kdbus, G_TYPE_KDBUS, GKdbusPrivate);
  kdbus->priv->fd = -1;
  kdbus->priv->path = NULL;
  kdbus->priv->buffer_ptr = NULL;
}

static gboolean
g_kdbus_initable_init (GInitable *initable,
			GCancellable *cancellable,
			GError  **error)
{
  GKdbus  *kdbus;

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
 * g_kdbus_get_fd:
 * @kdbus: a #GKdbus.
 *
 * Returns: the file descriptor of the kdbus.
 */
gint
g_kdbus_get_fd (GKdbus *kdbus)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus), FALSE);

  return kdbus->priv->fd;
}

/**
 * g_kdbus_connect:
 * @kdbus: a #Gkdbus.
 */
gboolean
g_kdbus_open (GKdbus         *kdbus,
	      const gchar    *address,
              GCancellable   *cancellable,
	      GError         **error)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus), FALSE);

  kdbus->priv->fd = open(address, O_RDWR|O_CLOEXEC|O_NONBLOCK);

  return TRUE;
}

/**
 * g_kdbus_close:
 * @kdbus: a #GKdbus
 * @error: #GError for error reporting, or %NULL to ignore.
 *
 */
gboolean
g_kdbus_close (GKdbus  *kdbus,
		GError  **error)
{
  // TODO

  close(kdbus->priv->fd);

  kdbus->priv->closed = TRUE;
  kdbus->priv->fd = -1;
  
  return TRUE;
}

/**
 * g_kdbus_is_closed:
 * @kdbus: a #GKdbus
 *
 * Checks whether a kdbus is closed.
 *
 * Returns: %TRUE if kdbus is closed, %FALSE otherwise
 */
gboolean
g_kdbus_is_closed (GKdbus *kdbus)
{
  g_return_val_if_fail (G_IS_KDBUS (kdbus), FALSE);

  return kdbus->priv->closed;
}

/*
 * g_kdbus_decode_msg:
 * @kdbus_msg: kdbus message received into buffer
 *
 */
static int 
g_kdbus_decode_msg(struct kdbus_msg *msg, 
                   void      *data)
{
  // TODO
  return 0;
}

/*
 * g_kdbus_receive:
 * @kdbus: a #GKdbus
 *
 * TODO handle errors
 */
gssize
g_kdbus_receive (GKdbus       *kdbus,
                 void         *data,
		             GError       **error)
{
  int ret_size;
  guint64 __attribute__ ((__aligned__(8))) offset;
  struct kdbus_msg *msg;

  // get memory offset of msg
  again:
  if (ioctl(kdbus->priv->fd, KDBUS_CMD_MSG_RECV, &offset) < 0)
  {
	  if(errno == EINTR)
		  goto again;
	  return -1;
  }

  msg = (struct kdbus_msg *)((gchar*)kdbus->priv->buffer_ptr + offset);

  ret_size = g_kdbus_decode_msg(msg, data);

  // Release memory occupied by msg
  again2:
	if (ioctl(kdbus->priv->fd, KDBUS_CMD_MSG_RELEASE, &offset) < 0)
	{
		if(errno == EINTR)
			goto again2;
		return -1;
	}
  
  return ret_size;
}

/**
 * g_kdbus_send_message:
 * @kdbus: a #GKdbus
 */
gssize
g_kdbus_send_message (GKdbus          *kdbus,
                      GDBusMessage    *dbus_msg,
                      GDBusConnection *connection,
		                  GError          **error)
{
  struct kdbus_msg* kmsg;
  struct kdbus_item *item;
  guint64 kmsg_size = 0;
  const gchar *dst;
  guint64 dst_id = KDBUS_DST_ID_BROADCAST;
  gsize blob_size;
  guchar *blob;

  // get dbus message blob
  blob = g_dbus_message_to_blob(dbus_msg, &blob_size, 0, error);
  g_print ("kdbus_send_message blob_size: %i", (int)blob_size);
  
  // get dst name
  dst = g_dbus_message_get_destination(dbus_msg);
  g_print ("kdbus_send_message destination name: %s", dst);

  kmsg_size = sizeof(struct kdbus_msg);
  kmsg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec)); // vector for blob

  if (dst)
  	kmsg_size += KDBUS_ITEM_SIZE(strlen(dst) + 1);
  else if (dst_id == KDBUS_DST_ID_BROADCAST)
  	kmsg_size += KDBUS_PART_HEADER_SIZE + 32; /* TODO transport->bloom_size*/;

  kmsg = malloc(kmsg_size);
  if (!kmsg)
  {
  	// TODO debug/error
	  return -1;
  }

  memset(kmsg, 0, kmsg_size);
  kmsg->size = kmsg_size;
  kmsg->payload_type = KDBUS_PAYLOAD_DBUS1;
  kmsg->dst_id = dst ? 0 : dst_id;
  kmsg->src_id = strtoull(g_dbus_connection_get_unique_name(connection), NULL , 10);
  kmsg->cookie = g_dbus_message_get_serial(dbus_msg);

  g_print ("kdbus_send_message unique_name: %s", g_dbus_connection_get_unique_name(connection));

  // build message contents
  item = kmsg->items;

  MSG_ITEM_BUILD_VEC(blob, blob_size);

  if (dst)
	{
		item = KDBUS_PART_NEXT(item);
		item->type = KDBUS_MSG_DST_NAME;
		item->size = KDBUS_PART_HEADER_SIZE + strlen(dst) + 1;
		strcpy(item->str, dst);
	}
	else if (dst_id == KDBUS_DST_ID_BROADCAST)
	{
		item = KDBUS_PART_NEXT(item);
		item->type = KDBUS_MSG_BLOOM;
		item->size = KDBUS_PART_HEADER_SIZE + 32; /* TODO transport->bloom_size*/;
		// TODO strncpy(item->data, dbus_message_get_interface(message), transport->bloom_size);
	}

again:
	if (ioctl(kdbus->priv->fd, KDBUS_CMD_MSG_SEND, kmsg))
	{
		if(errno == EINTR)
			goto again;
    else
      g_warning ("g_kdbus_send_message: ioctl error sending kdbus message: %d (%m)", errno);
  }

  free(kmsg);

  return blob_size;
}

/***************************************************************************************************************


/**
 * g_kdbus_send:
 * @kdbus: a #GKdbus
 */
/*gssize
g_kdbus_send (GKdbus       *kdbus,
	       const gchar   *buffer,
	       gsize          size,
	       GCancellable  *cancellable,
	       GError       **error)
{
  // TODO
}*/




/**
 * g_kdbus_receive_message:
 * @kdbus: a #Gkdbus
 */
/*gssize
g_kdbus_receive_message (Gkdbus                 *kdbus,
			  GkdbusAddress         **address,
			  GInputVector            *vectors,
			  gint                     num_vectors,
			  GkdbusControlMessage ***messages,
			  gint                    *num_messages,
			  gint                    *flags,
			  GCancellable            *cancellable,
			  GError                 **error)
{
  //TODO
}*/
