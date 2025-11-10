import os
import json
from flask import Blueprint, render_template, request, current_app

bp = Blueprint('browser_backup', __name__)

@bp.route('/browser-backups', methods=['GET'])
def browser_backups():
    backup_root = os.path.expanduser(r"~\BrowserPasswordBackups")
    backups = []
    if os.path.isdir(backup_root):
        backups = sorted([d for d in os.listdir(backup_root) if os.path.isdir(os.path.join(backup_root, d))], reverse=True)
    selected_backup = request.args.get('backup') or (backups[0] if backups else None)
    browser_files = {}
    if selected_backup:
        backup_dir = os.path.join(backup_root, selected_backup)
        for browser in ['chrome', 'edge', 'brave', 'opera']:
            json_path = os.path.join(backup_dir, f"{browser}_passwords.json")
            if os.path.exists(json_path):
                try:
                    with open(json_path, encoding='utf-8') as f:
                        browser_files[browser] = json.load(f)
                except Exception:
                    browser_files[browser] = []
            else:
                browser_files[browser] = []
    return render_template('browser_backup_preview.html', backups=backups, selected_backup=selected_backup, browser_files=browser_files)