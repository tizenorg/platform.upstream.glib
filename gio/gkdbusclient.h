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

#ifndef __G_KDBUS_CLIENT_H__
#define __G_KDBUS_CLIENT_H__

#if !defined (__GIO_GIO_H_INSIDE__) && !defined (GIO_COMPILATION)
#error "Only <gio/gio.h> can be included directly."
#endif

#include <glib-object.h>
#include <gio/giotypes.h>

G_BEGIN_DECLS

#define G_TYPE_KDBUS_CLIENT                                (g_kdbus_client_get_type ())
#define G_KDBUS_CLIENT(inst)                               (G_TYPE_CHECK_INSTANCE_CAST ((inst),                     \
                                                             G_TYPE_KDBUS_CLIENT, GKdbusClient))
#define G_KDBUS_CLIENT_CLASS(class)                        (G_TYPE_CHECK_CLASS_CAST ((class),                       \
                                                             G_TYPE_KDBUS_CLIENT, GKdbusClientClass))
#define G_IS_KDBUS_CLIENT(inst)                            (G_TYPE_CHECK_INSTANCE_TYPE ((inst),                     \
                                                             G_TYPE_KDBUS_CLIENT))
#define G_IS_KDBUS_CLIENT_CLASS(class)                     (G_TYPE_CHECK_CLASS_TYPE ((class),                       \
                                                             G_TYPE_KDBUS_CLIENT))
#define G_KDBUS_CLIENT_GET_CLASS(inst)                     (G_TYPE_INSTANCE_GET_CLASS ((inst),                      \
                                                             G_TYPE_KDBUS_CLIENT, GKdbusClientClass))

typedef struct _GKdbusClientPrivate                        GKdbusClientPrivate;
typedef struct _GKdbusClientClass                          GKdbusClientClass;

struct _GKdbusClientClass
{
  GObjectClass parent_class;

  /* Padding for future expansion */
  void (*_g_reserved1) (void);
  void (*_g_reserved2) (void);
  void (*_g_reserved3) (void);
  void (*_g_reserved4) (void);
};

struct _GKdbusClient
{
  GObject parent_instance;
  GKdbusClientPrivate *priv;
};

GLIB_AVAILABLE_IN_ALL
GType                   g_kdbus_client_get_type                        (void) G_GNUC_CONST;

GLIB_AVAILABLE_IN_ALL
GKdbusClient           *g_kdbus_client_new                             (void);


GLIB_AVAILABLE_IN_ALL
GKdbusConnection *     g_kdbus_client_connect                          (GKdbusClient        *client,
                                                                         const gchar        *address,
                                                                         GCancellable       *cancellable,
                                                                         GError             **error);

G_END_DECLS

#endif /* __G_KDBUS_CLIENT_H___ */
