
import os
import sys
from pyupdater.client import Client
from client_config import CLIENT_CONFIG

def check_for_updates():
    client = Client(CLIENT_CONFIG)
    app_update = client.update_check(
        CLIENT_CONFIG['APP_NAME'],
        '1.0.0'  # Current version
    )
    
    if app_update:
        print("Update available!")
        app_update.download()
        if app_update.is_downloaded():
            print("Update downloaded. Extracting...")
            app_update.extract_restart()
            # This will restart the app with the new version
    else:
        print("No updates available.")

if __name__ == '__main__':
    check_for_updates()
