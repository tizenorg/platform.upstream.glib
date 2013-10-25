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
 * Authors: Lukasz Skalski <l.skalski@partner.samsung.com>
 * Authors: Michal Eljasiewicz <m.eljasiewic@samsung.com>
 */

#include "config.h"
#include "gkdbusclient.h"
#include <gio/gkdbusconnection.h>

G_DEFINE_TYPE (GKdbusClient, g_kdbus_client, G_TYPE_OBJECT);

struct _GKdbusClientPrivate
{
  GHashTable *app_proxies;
};


// TODO
static void
g_kdbus_client_init (GKdbusClient *client)
{
  client->priv = G_TYPE_INSTANCE_GET_PRIVATE (client,
					      G_TYPE_KDBUS_CLIENT,
					      GKdbusClientPrivate);
  client->priv->app_proxies = g_hash_table_new_full (g_str_hash,
						     g_str_equal,
						     g_free,
						     NULL);
}

// TODO
GKdbusClient *
g_kdbus_client_new (void)
{
  return g_object_new (G_TYPE_KDBUS_CLIENT, NULL);
}

// TODO
static void
g_kdbus_client_finalize (GObject *object)
{
  GKdbusClient *client = G_KDBUS_CLIENT (object);

  g_hash_table_unref (client->priv->app_proxies);
}

// TODO
static void
g_kdbus_client_get_property (GObject    *object,
			      guint       prop_id,
			      GValue     *value,
			      GParamSpec *pspec)
{
  //GKdbusClient *client = G_KDBUS_CLIENT (object);

  switch (prop_id)
    {
      default:
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

// TODO
static void
g_kdbus_client_set_property (GObject      *object,
			      guint         prop_id,
			      const GValue *value,
			      GParamSpec   *pspec)
{
  //GKdbusClient *client = G_KDBUS_CLIENT (object);

  switch (prop_id)
    {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

// TODO
static void
g_kdbus_client_class_init (GKdbusClientClass *class)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (class);

  g_type_class_add_private (class, sizeof (GKdbusClientPrivate));

  gobject_class->finalize = g_kdbus_client_finalize;
  gobject_class->set_property = g_kdbus_client_set_property;
  gobject_class->get_property = g_kdbus_client_get_property;
}

// TODO
GKdbusConnection *
g_kdbus_client_connect (GKdbusClient       *client,
			 const gchar       *address,
			 GCancellable      *cancellable,
			 GError            **error)
{
  GIOStream *connection = NULL;
  GError *last_error;
  last_error = NULL;

  while (connection == NULL)
    {

    if (g_cancellable_is_cancelled (cancellable))
      {
	    g_clear_error (error);
	    g_cancellable_set_error_if_cancelled (cancellable, error);
	    break;
      }

    connection = g_object_new(G_TYPE_KDBUS_CONNECTION,NULL);
    if (g_kdbus_connection_connect (G_KDBUS_CONNECTION (connection),
				       address, cancellable, &last_error))
      {
	    //g_print("It works :)\n");
      }
    else
	  {
	    g_object_unref (connection);
	    connection = NULL;
      }
    }
  return G_KDBUS_CONNECTION (connection);
}

