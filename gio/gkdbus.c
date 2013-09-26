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
#include <sys/mman.h>

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
  gint            peer_id;
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
  kdbus->priv->peer_id = -1;
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

/**
 * Registration on Kdbus bus.
 * Hello message + unique name + mapping memory for incoming messages.
 *
 * @returns #TRUE on success
 */
gboolean g_kdbus_register(GKdbus           *kdbus)
{
	struct kdbus_cmd_hello __attribute__ ((__aligned__(8))) hello;

	hello.conn_flags = KDBUS_HELLO_ACCEPT_FD/* |
			   KDBUS_HELLO_ATTACH_COMM |
			   KDBUS_HELLO_ATTACH_EXE |
			   KDBUS_HELLO_ATTACH_CMDLINE |
			   KDBUS_HELLO_ATTACH_CAPS |
			   KDBUS_HELLO_ATTACH_CGROUP |
			   KDBUS_HELLO_ATTACH_SECLABEL |
			   KDBUS_HELLO_ATTACH_AUDIT*/;
	hello.size = sizeof(struct kdbus_cmd_hello);
	hello.pool_size = RECEIVE_POOL_SIZE;

	if (ioctl(kdbus->priv->fd, KDBUS_CMD_HELLO, &hello))
	{
		g_print("Failed to send hello: %m, %d",errno);
		return FALSE;
	}

  kdbus->priv->peer_id = hello.id;
	g_print("-- Our peer ID is: %llu\n", hello.id);
	// TODO (ASK RADEK)transportS->bloom_size = hello.bloom_size;

	kdbus->priv->buffer_ptr = mmap(NULL, RECEIVE_POOL_SIZE, PROT_READ, MAP_SHARED, kdbus->priv->fd, 0);
	if (kdbus->priv->buffer_ptr == MAP_FAILED)
	{
		g_print("Error when mmap: %m, %d",errno);
		return FALSE;
	}

	return TRUE;
}

/*
 * g_kdbus_decode_msg:
 * @kdbus_msg: kdbus message received into buffer
 *
 */
static int 
g_kdbus_decode_msg(GKdbus           *kdbus,
                   struct kdbus_msg *msg, 
                   char             *data)
{
  const struct kdbus_item *item;
  int ret_size = 0;

  KDBUS_PART_FOREACH(item, msg, items)
	{
		if (item->size <= KDBUS_PART_HEADER_SIZE)
		{
			g_print("  +(%llu bytes) invalid data record\n", item->size);
			break;  //??? continue (because dbus will find error) or break
		}

		switch (item->type)
		{
			case KDBUS_MSG_PAYLOAD_OFF:
				memcpy(data, (char *)kdbus->priv->buffer_ptr + item->vec.offset, item->vec.size);
				data += item->vec.size;
				ret_size += item->vec.size;			

				g_print("  + KDBUS_MSG_PAYLOAD (%llu bytes) off=%llu size=%llu\n", item->size,
					(unsigned long long)item->vec.offset,
					(unsigned long long)item->vec.size);
			break;

      case KDBUS_MSG_REPLY_TIMEOUT:
				g_print("  + KDBUS_MSG_REPLY_TIMEOUT (%llu bytes) cookie=%llu\n", item->size, msg->cookie_reply);

				/* TODO
        message = generate_local_error_message(msg->cookie_reply, DBUS_ERROR_NO_REPLY, NULL);
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}

				ret_size = put_message_into_data(message, data);
        */
			break;

			case KDBUS_MSG_REPLY_DEAD:
				g_print("  + (%llu bytes) cookie=%llu\n", item->size, msg->cookie_reply);

        /* TODO
				message = generate_local_error_message(msg->cookie_reply, DBUS_ERROR_NAME_HAS_NO_OWNER, NULL);
				if(message == NULL)
				{
					ret_size = -1;
					goto out;
				}
        
				ret_size = put_message_into_data(message, data);
        */
			break;

      /* case ... */
    }
  }

  return ret_size;
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

  msg = (struct kdbus_msg *)((char*)kdbus->priv->buffer_ptr + offset);

  ret_size = g_kdbus_decode_msg(kdbus, msg, (char*)data);

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
                      gchar           *blob,
                      gsize           blob_size,
		                  GError          **error)
{
  struct kdbus_msg* kmsg;
  struct kdbus_item *item;
  guint64 kmsg_size = 0;
  const gchar *dst;
  guint64 dst_id = KDBUS_DST_ID_BROADCAST;
  
  // if message to org.Freedesktop.DBus then handle differently
  if(g_strcmp0(g_dbus_message_get_member(dbus_msg), "Hello") == 0)
  {
    g_print ("sending Hello message! \n");
  
    g_kdbus_register(kdbus); // TODO check return bool
    goto out;
  }

  g_print ("kdbus_send_message blob_size: %i \n", (int)blob_size);
  
  // get dst name
  dst = g_dbus_message_get_destination(dbus_msg);
  g_print ("kdbus_send_message destination name: %s \n", dst);

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
  kmsg->src_id = strtoull(g_dbus_message_get_sender(dbus_msg), NULL , 10);
  kmsg->cookie = g_dbus_message_get_serial(dbus_msg);

  g_print ("kdbus_send_message unique_name/message->sender: %s \n", g_dbus_message_get_sender(dbus_msg));

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
		// TODO (ASK RADEK) strncpy(item->data, dbus_message_get_interface(message), transport->bloom_size);
	}

again:
	if (ioctl(kdbus->priv->fd, KDBUS_CMD_MSG_SEND, kmsg))
	{
		if(errno == EINTR)
			goto again;
    else
      g_warning ("g_kdbus_send_message: ioctl error sending kdbus message: %d (%m) \n", errno);
  }

  free(kmsg);

out:
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
