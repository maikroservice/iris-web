import subprocess

import gnupg
import hashlib
import json
import os
import requests
import shutil
import tempfile
import time
from datetime import datetime
from flask_login import current_user
from flask_socketio import join_room, emit
from packaging import version
from pathlib import Path

from app import app, celery, socket_io
from app.datamgmt.manage.manage_srv_settings_db import get_server_settings_as_dict
from iris_interface import IrisInterfaceStatus as IStatus

log = app.logger


def update_log_to_socket(status, is_error=False):
    log.info(status)
    data = {
        "message": status,
        "is_error": is_error
    }
    socket_io.emit('update_status', data, to='iris_update_status', namespace='/server-updates')


def notify_server_off():
    socket_io.emit('server_has_turned_off', {}, to='iris_update_status', namespace='/server-updates')


def notify_update_failed():
    socket_io.emit('update_has_fail', {}, to='iris_update_status', namespace='/server-updates')


def update_log(status):
    update_log_to_socket(status)


def update_log_error(status):
    update_log_to_socket(status, is_error=True)


@socket_io.on('join-update', namespace='/server-updates')
def get_message(data):
    if not current_user.is_authenticated:
        return

    room = data['channel']
    join_room(room=room)

    emit('join', {'message': f"{current_user.user} just joined", 'is_error': False}, room=room,
         namespace='/server-updates')


@socket_io.on('update_ping', namespace='/server-updates')
def socket_on_update_ping(msg):
    emit('update_ping', {'message': f"Server connected", 'is_error': False},
         namespace='/server-updates')


@socket_io.on('update_get_current_version', namespace='/server-updates')
def socket_on_update_do_reboot(msg):
    socket_io.emit('update_current_version', {"version": app.config.get('IRIS_VERSION')}, to='iris_update_status',
                   namespace='/server-updates')


def notify_server_ready_to_reboot():
    socket_io.emit('server_ready_to_reboot', {}, to='iris_update_status', namespace='/server-updates')


def inner_init_server_update():
    has_updates, updates_content, release_config = is_updates_available()
    init_server_update(release_config)


def get_external_url(url):
    server_settings = get_server_settings_as_dict()
    proxies = server_settings.get('proxies')
    try:
        request = requests.get(url, proxies=proxies)
    except Exception as e:
        app.logger.error(e)
        return None

    return request


def get_latest_release():

    try:
        releases = get_external_url(app.config.get('RELEASE_URL'))
    except Exception as e:
        app.logger.error(e)
        return True, None

    if releases.status_code == 200:
        releases_j = releases.json()

        return False, releases_j[0]

    if releases.status_code == 403:
        return True, releases.json()

    return True, None


def get_release_assets(assets_url):

    try:
        release_assets = get_external_url(assets_url)
    except Exception as e:
        app.logger.error(e)
        return None

    if release_assets:
        return release_assets.json()

    return None


def is_updates_available():
    has_error, release = get_latest_release()

    current_version = app.config.get('IRIS_VERSION')

    if has_error:
        return False, release.get('message')

    release_version = release.get('name')

    if version.parse(current_version) < version.parse(release_version):
        return True, f'# New version {release_version} available\n\n{release.get("body")}', release

    else:
        return False, f'**Current server is up-to-date with {release_version}**', None


def init_server_update(release_config):

    if not release_config:
        update_log_error('Release config is empty. Please contact IRIS team')
        notify_update_failed()
        return False

    update_log('Fetching release assets info')
    has_error, temp_dir = download_release_assets(release_config.get('assets'))
    if has_error:
        update_log_error('Aborting upgrades - see previous errors')
        notify_update_failed()
        shutil.rmtree(temp_dir)
        return False

    has_error = verify_assets_signatures(temp_dir, release_config.get('assets'))
    if has_error:
        update_log_error('Aborting upgrades - see previous errors')
        notify_update_failed()
        shutil.rmtree(temp_dir)
        return False

    updates_config = verify_compatibility(temp_dir, release_config.get('assets'))
    if updates_config is None:
        update_log_error('Aborting upgrades - see previous errors')
        notify_update_failed()
        shutil.rmtree(temp_dir)
        return False

    update_log('Update files verified')
    update_log('Backing up current version')
    #has_error = update_backup_current_version()
    has_error = False
    if has_error:
        update_log_error('Aborting upgrades - see previous errors')
        notify_update_failed()
        shutil.rmtree(temp_dir)
        return False

    update_log('All checks passed. IRIS will turn off shortly and updates')
    update_log('Please don\'t leave the page - logging will resume here')
    update_log('Handing off to updater')

    notify_server_off()
    time.sleep(0.5)

    update_archive = Path(temp_dir) / updates_config.get('app_archive')
    call_ext_updater(update_archive=update_archive)

    import app
    app.socket_io.stop()

    return True


def call_ext_updater(update_archive):
    archive_name = update_archive.stem

    if os.getenv("DOCKERIZED"):
        source_dir = Path.cwd() / 'scripts'
        target_dir = Path.cwd()
    else:
        source_dir = Path.cwd().absolute() / 'scripts'
        target_dir = Path('../../update_server/test_update') # TODO change

    subprocess.Popen(["nohup", "/bin/bash", f"{source_dir}/iris_updater.sh",
                      update_archive.as_posix(),        # Update archive to unpack
                      target_dir.as_posix(),            # Target directory of update
                      archive_name,                     # Root directory of the archive
                      'iriswebapp'])                    # Target webapp

    return


def update_backup_current_version():
    date_time = datetime.now()

    root_backup = Path(app.config.get("BACKUP_PATH"))
    root_backup.mkdir(exist_ok=True)

    backup_dir = root_backup / f"server_backup_{date_time.timestamp()}"
    backup_dir.mkdir(exist_ok=True)
    if not backup_dir.is_dir():
        update_log_error(f"Unable to create directory {backup_dir} for backup. Aborting")
        return True

    if os.getenv("DOCKERIZED"):
        source_dir = Path.cwd()
    else:
        source_dir = Path.cwd().parent.absolute()

    try:
        update_log(f'Copying {source_dir} to {backup_dir}')
        shutil.copytree(source_dir, backup_dir, dirs_exist_ok=True)
    except Exception as e:
        update_log_error('Unable to backup current version')
        update_log_error(str(e))
        return False, ['Unable to backup current version', str(e)]

    update_log('Current version backed up')
    has_error = generate_backup_config_file(backup_dir)
    if has_error:
        return True

    return False


def generate_backup_config_file(backup_dir):
    backup_config = {
        "backup_date": datetime.now().timestamp(),
        "backup_version": app.config.get('IRIS_VERSION')
    }

    hashes_map = {}

    for entry in backup_dir.rglob('*'):

        if entry.is_file():
            sha256_hash = hashlib.sha256()

            with open(entry, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)

            hashes_map[entry.as_posix()] = sha256_hash.hexdigest()

    backup_config["hashes_map"] = hashes_map

    try:

        with open(backup_dir / "backup_config.json", 'w') as fconfig:
            json.dump(backup_config, fconfig, indent=4)

    except Exception as e:
        update_log_error('Unable to save configuration file')
        update_log_error(str(e))
        return True

    update_log('Backup configuration file generated')
    return False


def verify_compatibility(target_directory, release_assets_info):
    release_updates = None

    update_log('Verifying updates compatibilities')

    for release_asset in release_assets_info:
        asset_name = release_asset.get('name')
        if asset_name != 'release_updates.json':
            continue

        if (Path(target_directory) / asset_name).is_file():
            release_updates = Path(target_directory) / asset_name
            break

    if not release_updates:
        update_log_error('Unable to find release updates configuration file')
        return None

    try:
        with open(file=release_updates) as fin:
            updates_info = json.load(fin)
    except Exception as e:
        update_log_error('Unable to read release updates configuration file')
        update_log_error(str(e))
        update_log_error('Please contact DFIR-IRIS team')
        return None

    can_update = False
    accepted_versions = updates_info.get('accepted_versions')
    for av in accepted_versions:
        if version.parse(app.config.get('IRIS_VERSION')) == version.parse(av):
            can_update = True
            break

    if not can_update:
        update_log_error(f'Current version {app.config.get("IRIS_VERSION")} cannot '
                         f'be updated to {updates_info.get("target_version")} automatically')
        update_log_error(f'Supported versions are {updates_info.get("accepted_versions")}')
        return None

    update_log('Compatibly checks done. Good to go')

    return updates_info


def verify_assets_signatures(target_directory, release_assets_info):
    # Expects a signature for every assets
    has_error = False

    assets_check = {}

    for release_asset in release_assets_info:
        asset_name = release_asset.get('name')

        if not asset_name.endswith('.sig'):

            if (Path(target_directory) / asset_name).is_file():

                if (Path(target_directory) / f"{asset_name}.sig").is_file():
                    assets_check[Path(target_directory) / asset_name] = Path(target_directory) / f"{asset_name}.sig"

                else:
                    update_log_error(f"{asset_name} does not have a signature file")
                    has_error = True
            else:
                update_log_error(f"Could not find {Path(target_directory) / asset_name}")
                has_error = True

    if has_error:
        return has_error

    update_log("Importing DFIR-IRIS GPG key")
    gpg = gnupg.GPG()

    with open('dependencies/DFIR-IRIS_pkey.asc', 'rb') as pkey:
        import_result = gpg.import_keys(pkey.read())

    if import_result.count < 1:
        update_log_error(f'Unable to fetch {app.config.get("RELEASE_SIGNATURE_KEY")}')
        has_error = True

    for asset in assets_check:
        with open(assets_check[asset], 'rb') as fin:

            verified = gpg.verify_file(fin, data_filename=asset)

            if not verified.valid:

                update_log_error(f'{asset.name} does not have a valid signature (checked '
                                 f'against {assets_check[asset].name}). '
                                 f'Contact DFIR-IRIS team')
                update_log_error(f"Signature status : {verified.status}")
                has_error = True
                continue

            update_log(f"{asset.name} : signature validated")

    return has_error


def download_release_assets(release_assets_info):
    has_error = False
    temp_dir = tempfile.mkdtemp()

    for release_asset in release_assets_info:
        asset_name = release_asset.get('name')
        asset_url = release_asset.get('browser_download_url')

        # TODO: Check for available FS free space before downloading
        update_log(f'Downloading from {asset_url}')

        if not download_from_url(asset_url, Path(temp_dir) / asset_name):
            update_log_error('ERROR - Unable to save asset file to FS')
            has_error = True

    if has_error:
        update_log_error('Aborting upgrades - see previous errors')

    return has_error, temp_dir


def download_from_url(asset_url, target_file):

    with open(target_file, "wb") as file:
        response = get_external_url(asset_url)
        file.write(response.content)

    return Path(target_file).is_file()


@celery.task(bind=True)
def task_update_worker(self, update_to_version):
    celery.control.revoke(self.request.id)
    celery.control.broadcast("pool_restart", arguments={"reload_modules": True})

    return IStatus.I2Success(message="Pool restarted")
