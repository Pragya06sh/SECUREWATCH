"""
SecureWatch Alerts
Desktop notifications with safe fallback and zero thread exceptions on Windows.
"""
import logging
import sys
import threading

logger = logging.getLogger("securewatch.alerts")

# Suppress unhandled balloon_tip thread exceptions on Windows without a system tray
def _quiet_thread_excepthook(args):
    if args.exc_value and "Shell_NotifyIcon" in str(args.exc_value):
        return
    if hasattr(threading, "__excepthook__"):
        threading.__excepthook__(args)

if hasattr(threading, "excepthook"):
    threading.excepthook = _quiet_thread_excepthook

_plyer_notify = None
try:
    from plyer import notification
    _plyer_notify = notification.notify
except Exception:
    logger.warning("plyer not available — desktop notifications in log only")


def send_alert(message: str, title: str = "SecureWatch — Attack Detected"):
    """Send a desktop alert. Logs warning and triggers desktop notification if supported."""
    logger.warning(f"ALERT: {title} — {message}")
    if _plyer_notify:
        try:
            _plyer_notify(
                title=title,
                message=message,
                timeout=3
            )
        except Exception:
            pass