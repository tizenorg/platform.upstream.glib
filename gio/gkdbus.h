/* GIO - GLib Input, Output and Streaming Library
 *
 * Copyright (C) 2015 Samsung Electronics
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
 * Author: Lukasz Skalski       <l.skalski@samsung.com>
 * Author: Michal Eljasiewicz   <m.eljasiewic@samsung.com>
 */

#ifndef __G_KDBUS_H__
#define __G_KDBUS_H__

#if !defined (GIO_COMPILATION)
#error "gkdbus.h is a private header file."
#endif

#include <gio/giotypes.h>
#include "gdbusprivate.h"

#define G_TYPE_KDBUS_WORKER                                (g_kdbus_worker_get_type ())
#define G_KDBUS_WORKER(inst)                               (G_TYPE_CHECK_INSTANCE_CAST ((inst),                     \
                                                            G_TYPE_KDBUS_WORKER, GKDBusWorker))
#define G_KDBUS_WORKER_CLASS(class)                        (G_TYPE_CHECK_CLASS_CAST ((class),                       \
                                                            G_TYPE_KDBUS_WORKER, GKDBusWorkerClass))
#define G_IS_KDBUS_WORKER(inst)                            (G_TYPE_CHECK_INSTANCE_TYPE ((inst),                     \
                                                            G_TYPE_KDBUS_WORKER))
#define G_IS_KDBUS_WORKER_CLASS(class)                     (G_TYPE_CHECK_CLASS_TYPE ((class),                       \
                                                            G_TYPE_KDBUS_WORKER))
#define G_KDBUS_WORKER_GET_CLASS(inst)                     (G_TYPE_INSTANCE_GET_CLASS ((inst),                      \
                                                            G_TYPE_KDBUS_WORKER, GKDBusWorkerClass))
typedef enum {
  G_DBUS_CREDS_NONE = 0,
  G_DBUS_CREDS_PID = (1<<0),
  G_DBUS_CREDS_UID = (1<<1),
  G_DBUS_CREDS_UNIQUE_NAME = (1<<2),
  G_DBUS_CREDS_SEC_LABEL = (1<<3)
} GDBusCredentialsFlags;

typedef struct
{
  guint   pid;
  guint   uid;
  gchar  *unique_name;
  gchar  *sec_label;
} GDBusCredentials;

typedef struct
{
  GDBusMessage  *message;
  uid_t          sender_euid;
  gid_t          sender_egid;
  gchar         *sender_seclabel;
  gchar         *sender_names;
} GKDBusMessage;

typedef struct _GKDBusWorker                                  GKDBusWorker;

void                  _g_kdbus_worker_associate              (GKDBusWorker                             *worker,
                                                              GDBusCapabilityFlags                      capabilities,
                                                              GDBusWorkerMessageReceivedCallback        message_received_callback,
                                                              GDBusWorkerMessageAboutToBeSentCallback   message_about_to_be_sent_callback,
                                                              GDBusWorkerDisconnectedCallback           disconnected_callback,
                                                              gpointer                                  user_data);

GType                  g_kdbus_worker_get_type               (void);

GKDBusWorker *        _g_kdbus_worker_new                    (const gchar         *address,
                                                              GError             **error);

void                  _g_kdbus_worker_unfreeze               (GKDBusWorker        *worker);

gboolean              _g_kdbus_worker_send_message           (GKDBusWorker        *worker,
                                                              GDBusMessage        *message,
                                                              gint                 timeout_msec,
                                                              GError             **error);

gboolean              _g_kdbus_worker_send_message_sync      (GKDBusWorker        *worker,
                                                              GDBusMessage        *message,
                                                              GDBusMessage       **out_reply,
                                                              gint                 timeout_msec,
                                                              GCancellable        *cancellable,
                                                              GError             **error);

void                  _g_kdbus_worker_stop                   (GKDBusWorker        *worker);

gboolean              _g_kdbus_worker_flush_sync             (GKDBusWorker        *worker);

void                  _g_kdbus_worker_close                  (GKDBusWorker        *worker,
                                                              GTask               *task);

/* ---------------------------------------------------------------------------------------------------- */

gboolean              _g_kdbus_open                          (GKDBusWorker        *worker,
                                                              const gchar         *address,
                                                              GError             **error);

gboolean              _g_kdbus_close                         (GKDBusWorker        *worker);

gboolean              _g_kdbus_is_closed                     (GKDBusWorker        *worker);

/* ---------------------------------------------------------------------------------------------------- */

const gchar *               _g_kdbus_Hello                           (GKDBusWorker        *worker,
                                                                      GError             **error);

gchar *                     _g_kdbus_GetBusId                        (GKDBusWorker        *worker,
                                                                      GError             **error);

GBusRequestNameReplyFlags   _g_kdbus_RequestName                     (GKDBusWorker        *worker,
                                                                      const gchar         *name,
                                                                      GBusNameOwnerFlags   flags,
                                                                      GError             **error);

GBusReleaseNameReplyFlags   _g_kdbus_ReleaseName                     (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      GError          **error);

gchar **                    _g_kdbus_GetListNames                    (GKDBusWorker     *worker,
                                                                      gboolean          activatable,
                                                                      GError          **error);

gchar **                    _g_kdbus_GetListQueuedOwners             (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      GError          **error);

gboolean                    _g_kdbus_NameHasOwner                    (GKDBusWorker     *connection,
                                                                      const gchar      *name,
                                                                      GError          **error);

gchar *                     _g_kdbus_GetNameOwner                    (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      GError          **error);

pid_t                       _g_kdbus_GetConnectionUnixProcessID      (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      GError          **error);

uid_t                       _g_kdbus_GetConnectionUnixUser           (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      GError          **error);

gchar *                     _g_kdbus_GetConnectionSecurityLabel      (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      GError          **error);

GBusStartServiceReplyFlags  _g_kdbus_StartServiceByName              (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      guint32           flags,
                                                                      GError          **error);

gboolean                    _g_kdbus_AddMatch                        (GKDBusWorker     *worker,
                                                                      const gchar      *match_rule,
                                                                      GError          **error);

gboolean                    _g_kdbus_RemoveMatch                     (GKDBusWorker     *worker,
                                                                      const gchar      *match_rule,
                                                                      GError          **error);

GDBusCredentials *          _g_kdbus_GetConnInfo                     (GKDBusWorker     *worker,
                                                                      const gchar      *name,
                                                                      guint             flags,
                                                                      GError          **error);

/* ---------------------------------------------------------------------------------------------------- */

gboolean              _g_kdbus_subscribe_name_acquired               (GKDBusWorker     *worker,
                                                                      const gchar      *match_rule,
                                                                      const gchar      *name,
                                                                      GError          **error);

gboolean              _g_kdbus_subscribe_name_lost                   (GKDBusWorker     *worker,
                                                                      const gchar      *match_rule,
                                                                      const gchar      *name,
                                                                      GError          **error);

gboolean              _g_kdbus_subscribe_name_owner_changed          (GKDBusWorker     *worker,
                                                                      const gchar      *match_rule,
                                                                      const gchar      *name,
                                                                      GError          **error);

/* ---------------------------------------------------------------------------------------------------- */

G_END_DECLS

#endif /* __G_KDBUS_H__ */
