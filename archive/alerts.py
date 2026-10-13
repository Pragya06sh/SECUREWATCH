from plyer import notification

def send_alert(message):

    notification.notify(
        title="Bluetooth Attack Detected",
        message=message,
        timeout=5
    )