from flask import Flask, render_template, request, redirect, url_for, jsonify, session, abort
import os
import sys
import json
import hashlib
import random
import string
from datetime import datetime, timedelta
import shutil
import urllib.parse
import requests

app = Flask(__name__, static_folder='.', static_url_path='/')
app.secret_key = ''.join(random.choices(string.ascii_letters + string.digits, k=24))

# IP访问限制配置
IP_LIMIT_CONFIG = {
    'max_attempts': 10,  # 最大失败尝试次数
    'block_time': 5,     # 拉黑时间（分钟）
    'blocked_ips': {},   # 存储被拉黑的IP及解除时间
    'failed_attempts': {}  # 存储各IP的失败尝试记录
}

# 配置
UPLOAD_FOLDER = './uploads'
ADMIN_CONFIG_FILE = './js/all/adminset.json'
FILE_DATA_FILE = './js/all/files_data.json'
DEFAULT_MAX_FILE_SIZE_MB = 50

# 获取用户IP地址
def get_client_ip():
    if request.headers.getlist('X-Forwarded-For'):
        ip = request.headers.getlist('X-Forwarded-For')[0]
    else:
        ip = request.remote_addr
    return ip

# 检查IP是否被拉黑
def is_ip_blocked(ip):
    current_time = datetime.now().timestamp()
    
    # 检查并移除已过期的黑名单
    blocked_ips_to_remove = []
    for blocked_ip, unblock_time in IP_LIMIT_CONFIG['blocked_ips'].items():
        if current_time > unblock_time:
            blocked_ips_to_remove.append(blocked_ip)
    
    for blocked_ip in blocked_ips_to_remove:
        del IP_LIMIT_CONFIG['blocked_ips'][blocked_ip]
        if blocked_ip in IP_LIMIT_CONFIG['failed_attempts']:
            del IP_LIMIT_CONFIG['failed_attempts'][blocked_ip]
    
    # 检查当前IP是否被拉黑
    return ip in IP_LIMIT_CONFIG['blocked_ips']

# 更新IP的失败尝试次数
def update_failed_attempts(ip, endpoint_type):
    # endpoint_type: 'verify_code' 或 'download_file'
    current_time = datetime.now().timestamp()
    
    if ip not in IP_LIMIT_CONFIG['failed_attempts']:
        IP_LIMIT_CONFIG['failed_attempts'][ip] = {
            'verify_code': [],
            'download_file': []
        }
    
    # 记录这次失败尝试
    IP_LIMIT_CONFIG['failed_attempts'][ip][endpoint_type].append(current_time)
    
    # 清理过期的失败记录（保留最近10分钟的）
    cutoff_time = current_time - 10 * 60
    IP_LIMIT_CONFIG['failed_attempts'][ip][endpoint_type] = [
        t for t in IP_LIMIT_CONFIG['failed_attempts'][ip][endpoint_type] if t > cutoff_time
    ]
    
    # 检查是否达到最大失败次数
    if len(IP_LIMIT_CONFIG['failed_attempts'][ip][endpoint_type]) >= IP_LIMIT_CONFIG['max_attempts']:
        # 拉黑该IP
        block_time = current_time + IP_LIMIT_CONFIG['block_time'] * 60
        IP_LIMIT_CONFIG['blocked_ips'][ip] = block_time
        # 清空失败记录
        IP_LIMIT_CONFIG['failed_attempts'][ip] = {
            'verify_code': [],
            'download_file': []
        }
        return True  # 已拉黑
    
    return False  # 未拉黑

# 重置IP的失败尝试次数
def reset_failed_attempts(ip, endpoint_type):
    if ip in IP_LIMIT_CONFIG['failed_attempts']:
        IP_LIMIT_CONFIG['failed_attempts'][ip][endpoint_type] = []

# 确保目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('./js/all', exist_ok=True)

# 检查是否已初始化
def check_initialized():
    return os.path.exists(ADMIN_CONFIG_FILE)

# 读取管理员配置
def read_admin_config():
    if check_initialized():
        with open(ADMIN_CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            # 确保配置文件包含所有必要字段
            if 'max_file_size' not in config:
                config['max_file_size'] = DEFAULT_MAX_FILE_SIZE_MB
            if 'announcement' not in config:
                config['announcement'] = ''
            save_admin_config(config)
            return config
    return None

# 保存管理员配置
def save_admin_config(config):
    with open(ADMIN_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)

# 获取当前最大文件大小（MB）
def get_max_file_size():
    config = read_admin_config()
    if config and 'max_file_size' in config:
        return config['max_file_size']
    return DEFAULT_MAX_FILE_SIZE_MB

# 获取当前公告
def get_announcement():
    config = read_admin_config()
    if config and 'announcement' in config:
        return config['announcement']
    return ''

# 读取文件数据
def read_file_data():
    if os.path.exists(FILE_DATA_FILE):
        with open(FILE_DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

# 保存文件数据
def save_file_data(data):
    with open(FILE_DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

# 生成随机4位数取件码(1000-9999)
def generate_code():
    file_data = read_file_data()
    while True:
        code = str(random.randint(1000, 9999))
        if code not in file_data:
            return code

# 生成随机20位数字文件名
def generate_random_filename():
    return ''.join(random.choices(string.digits, k=20))

# 安全地获取文件扩展名
def get_safe_extension(filename):
    if '.' in filename:
        ext = filename.rsplit('.', 1)[1].lower()
        # 只允许字母和数字的扩展名，防止路径遍历
        if ext.isalnum():
            return ext
    return ''

# 验证文件路径安全性，防止路径遍历攻击
def validate_file_path(file_path):
    """
    验证文件路径是否安全，防止路径遍历攻击
    """
    # 确保路径在指定的上传目录内
    upload_dir = os.path.abspath(UPLOAD_FOLDER)
    file_abs_path = os.path.abspath(file_path)
    
    # 检查文件路径是否在上传目录内
    if not file_abs_path.startswith(upload_dir):
        raise ValueError(f"文件路径不安全: {file_path}")
    
    # 只检查文件名部分是否安全，而不是整个路径
    filename = os.path.basename(file_path)
    
    # 检查文件名是否只包含安全字符（数字）
    if not filename.isdigit():
        raise ValueError(f"文件名不安全: {filename}")
    
    # 检查文件名是否包含危险的字符或路径遍历序列
    dangerous_patterns = ['..', '~', '/', '\\']
    for pattern in dangerous_patterns:
        if pattern in filename:
            raise ValueError(f"文件路径包含危险字符: {filename}")
    
    return True

# 检查文件是否过期
def check_expired_files():
    file_data = read_file_data()
    current_time = datetime.now().timestamp()
    expired_codes = []
    
    for code, info in file_data.items():
        if current_time > info['expire_time']:
            # 删除文件
            file_path = os.path.join(UPLOAD_FOLDER, info['filename'])
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
            expired_codes.append(code)
    
    # 移除过期记录
    for code in expired_codes:
        del file_data[code]
    
    if expired_codes:
        save_file_data(file_data)

# 禁止直接访问敏感文件
@app.route('/js/all/adminset.json')
@app.route('/js/all/files_data.json')
def block_sensitive_files():
    return abort(403, description='拒绝直接读取内部配置信息，请按正常流程调用api')

# 首页路由
@app.route('/')
def index():
    # 检查是否需要初始化
    if not check_initialized():
        return redirect(url_for('initialize'))
    
    # 检查并清理过期文件
    check_expired_files()
    
    return app.send_static_file('index.html')

# 初始化路由
@app.route('/initialize', methods=['GET', 'POST'])
def initialize():
    if check_initialized():
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        if password:
            # MD5加密密码
            md5_password = hashlib.md5(password.encode()).hexdigest()
            # 创建包含所有必要字段的配置
            save_admin_config({
                'password': md5_password,
                'max_file_size': DEFAULT_MAX_FILE_SIZE_MB,
                'announcement': ''
            })
            # 创建空的文件数据文件
            save_file_data({})
            return redirect(url_for('index'))
    
    return render_template('initialize.html')

# 管理员登录路由
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if not check_initialized():
        return redirect(url_for('initialize'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        admin_config = read_admin_config()
        
        if admin_config and hashlib.md5(password.encode()).hexdigest() == admin_config['password']:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin_login.html', error='密码错误')
    
    return render_template('admin_login.html')

# 管理员面板路由
@app.route('/admin/panel')
def admin_panel():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    # 检查并清理过期文件
    check_expired_files()
    
    # 获取文件数据
    file_data = read_file_data()
    
    # 格式化过期时间
    for code, info in file_data.items():
        expire_time = datetime.fromtimestamp(info['expire_time'])
        info['formatted_expire_time'] = expire_time.strftime('%Y-%m-%d %H:%M:%S')
    
    # 获取当前设置
    max_file_size = get_max_file_size()
    announcement = get_announcement()
    
    # 获取OneBot设置
    admin_config = read_admin_config()
    onebot_port = admin_config.get('onebot_port', '') if admin_config else ''
    onebot_push = admin_config.get('onebot_push', False) if admin_config else False
    onebot_group_id = admin_config.get('onebot_group_id', '') if admin_config else ''
    
    return render_template('admin_panel.html', files=file_data, max_file_size=max_file_size, announcement=announcement, onebot_port=onebot_port, onebot_push=onebot_push, onebot_group_id=onebot_group_id)

# 管理员登出路由
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

# 删除文件路由
@app.route('/admin/delete_file/<code>')
def delete_file(code):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    file_data = read_file_data()
    if code in file_data:
        # 删除文件
        file_path = os.path.join(UPLOAD_FOLDER, file_data[code]['filename'])
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except:
                pass
        # 获取原始文件名
        original_filename = file_data[code]['original_filename']
        # 删除记录
        del file_data[code]
        save_file_data(file_data)
        
        # 如果启用了OneBot推送，发送删除文件通知
        send_onebot_message('delete_file', filename=original_filename)
    
    return redirect(url_for('admin_panel'))

# 修改过期时间路由
@app.route('/admin/update_expire/<code>', methods=['POST'])
def update_expire(code):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    hours = request.form.get('hours', type=int)
    if hours and hours > 0:
        file_data = read_file_data()
        if code in file_data:
            new_expire_time = (datetime.now() + timedelta(hours=hours)).timestamp()
            file_data[code]['expire_time'] = new_expire_time
            file_data[code]['expire_hours'] = hours
            save_file_data(file_data)
    
    return redirect(url_for('admin_panel'))

# 上传页面路由
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not check_initialized():
        return redirect(url_for('initialize'))
    
    # 获取当前最大文件大小
    max_file_size_mb = get_max_file_size()
    max_file_size_bytes = max_file_size_mb * 1024 * 1024
    
    if request.method == 'POST':
        # 检查是否有文件上传
        if 'file' not in request.files:
            return render_template('upload.html', error='请选择要上传的文件')
        
        file = request.files['file']
        if file.filename == '':
            return render_template('upload.html', error='请选择要上传的文件')
        
        # 检查文件大小
        file.seek(0, 2)  # 移动到文件末尾
        file_size = file.tell()
        file.seek(0)  # 移回文件开头
        
        if file_size > max_file_size_bytes:
            return render_template('upload.html', error=f'文件大小不能超过{max_file_size_mb}MB')
        
        # 获取有效期
        expire_hours = request.form.get('expire_hours', type=int)
        if not expire_hours or expire_hours not in [1, 3, 10, 24]:
            return render_template('upload.html', error='请选择有效的有效期')
        
        # 生成取件码
        code = generate_code()
        
        # 生成随机文件名并获取安全扩展名
        random_filename = generate_random_filename()
        file_extension = get_safe_extension(file.filename)
        
        # 保存文件（使用随机文件名，不包含扩展名）
        file_path = os.path.join(UPLOAD_FOLDER, random_filename)
        
        # 验证文件路径安全性
        validate_file_path(file_path)
        
        file.save(file_path)
        
        # 计算过期时间
        expire_time = (datetime.now() + timedelta(hours=expire_hours)).timestamp()
        
        # 保存文件信息
        file_data = read_file_data()
        file_data[code] = {
            'filename': random_filename,
            'original_filename': file.filename,
            'extension': file_extension,
            'upload_time': datetime.now().timestamp(),
            'expire_time': expire_time,
            'expire_hours': expire_hours,
            'size': file_size
        }
        save_file_data(file_data)
        
        # 如果启用了OneBot推送，发送文件上传通知
        send_onebot_message('upload_file', filename=file.filename)
        
        return render_template('upload.html', success=True, code=code)
    
    return render_template('upload.html')


# 更新管理员设置路由
@app.route('/admin/update_settings', methods=['POST'])
def update_admin_settings():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    admin_config = read_admin_config()
    if not admin_config:
        return redirect(url_for('admin_login'))
    
    # 记录原始配置值，用于判断哪些设置被修改
    original_max_file_size = admin_config.get('max_file_size')
    original_onebot_push = admin_config.get('onebot_push', False)
    original_onebot_port = admin_config.get('onebot_port')
    original_onebot_group_id = admin_config.get('onebot_group_id')
    original_announcement = admin_config.get('announcement', '')
    
    error = None
    success = None
    
    # 标志变量，用于判断是否修改了背景图或图标
    background_image_updated = False
    favicon_updated = False
    
    # 获取表单数据
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    max_file_size = request.form.get('max_file_size', type=int)
    announcement = request.form.get('announcement', '')
    
    # 处理密码修改
    if current_password or new_password or confirm_password:
        # 检查当前密码是否正确
        if not current_password:
            error = '请输入当前密码'
        elif hashlib.md5(current_password.encode()).hexdigest() != admin_config['password']:
            error = '当前密码错误'
        elif not new_password:
            error = '请输入新密码'
        elif new_password != confirm_password:
            error = '两次输入的新密码不一致'
        else:
            # 更新密码
            admin_config['password'] = hashlib.md5(new_password.encode()).hexdigest()
            success = '密码更新成功'
    
    # 处理最大文件大小修改
    if max_file_size is not None:
        if max_file_size < 1 or max_file_size > 1024:
            error = error or '最大文件大小必须在1-1024MB之间'
        else:
            admin_config['max_file_size'] = max_file_size
            if not error:
                success = success or '设置更新成功'
    
    # 处理公告修改
    # 只有当表单中包含announcement字段并且有值时才更新公告内容
    # 这样当用户只修改界面设置（不包含announcement字段）时，不会覆盖原有公告
    if 'announcement' in request.form and request.form.get('announcement') is not None:
        admin_config['announcement'] = announcement
    
    # 处理OneBot设置
    # 只有当表单中包含相应字段时才更新设置，避免只修改界面设置时覆盖原有设置
    if 'onebot_push' in request.form:
        # checkbox提交时，存在表示勾选，不存在表示未勾选
        admin_config['onebot_push'] = True
    elif 'onebot_push' not in request.form and 'onebot_port' not in request.form and 'onebot_group_id' not in request.form:
        # 如果表单中不包含任何OneBot相关字段，则不修改现有设置
        pass
    else:
        # 如果表单中包含其他OneBot相关字段但不包含onebot_push，则视为未勾选
        admin_config['onebot_push'] = False
    
    if 'onebot_port' in request.form:
        onebot_port = request.form.get('onebot_port')
        if onebot_port:
            try:
                port = int(onebot_port)
                if 1024 <= port <= 65535:
                    admin_config['onebot_port'] = port
                else:
                    error = error or '端口号必须在1024-65535之间'
            except ValueError:
                error = error or '请输入有效的端口号'
    
    if 'onebot_group_id' in request.form:
        onebot_group_id = request.form.get('onebot_group_id')
        if onebot_group_id:
            # 验证QQ群号格式（纯数字）
            if not onebot_group_id.isdigit():
                error = error or 'QQ群号必须是纯数字'
            else:
                admin_config['onebot_group_id'] = onebot_group_id
    
    # 处理背景图上传
    if 'background_image' in request.files:
        background_image = request.files['background_image']
        if background_image and background_image.filename:
            # 检查文件类型
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp'}
            file_ext = background_image.filename.rsplit('.', 1)[1].lower() if '.' in background_image.filename else ''
            if file_ext not in allowed_extensions:
                error = error or '不支持的图片格式，请上传PNG、JPG、JPEG、GIF或BMP格式的图片'
            else:
                try:
                    # 确保背景图目录存在
                    bg_dir = os.path.join(app.root_path, 'css', 'all')
                    if not os.path.exists(bg_dir):
                        os.makedirs(bg_dir)
                    
                    # 保存上传的背景图，替换现有的bg.png
                    bg_path = os.path.join(bg_dir, 'bg.png')
                    # 读取上传的图片并转换为PNG格式保存
                    from PIL import Image
                    with Image.open(background_image) as img:
                        # 确保图片尺寸合理
                        max_size = (2560, 1440)  # 最大尺寸限制
                        img.thumbnail(max_size, Image.LANCZOS)
                        img.save(bg_path, 'PNG')
                    
                    background_image_updated = True
                    success = '背景图更新成功' if not success else success
                except Exception as e:
                    error = error or f'上传背景图时出错: {str(e)}'

    
    # 处理网站图标上传
    if 'favicon' in request.files:
        favicon = request.files['favicon']
        if favicon and favicon.filename:
            # 检查文件类型
            allowed_extensions = {'png'}
            file_ext = favicon.filename.rsplit('.', 1)[1].lower() if '.' in favicon.filename else ''
            if file_ext not in allowed_extensions:
                error = error or '不支持的图标格式，请上传PNG格式的图片'
            else:
                try:
                    # 确保图标目录存在
                    favicon_dir = os.path.join(app.root_path, 'css', 'all')
                    if not os.path.exists(favicon_dir):
                        os.makedirs(favicon_dir)
                    
                    # 保存上传的图标，替换现有的icon.png
                    favicon_path = os.path.join(favicon_dir, 'icon.png')
                    # 读取上传的图片并转换为PNG格式保存
                    from PIL import Image
                    with Image.open(favicon) as img:
                        # 确保图标尺寸合理
                        max_size = (256, 256)  # 最大尺寸限制
                        img.thumbnail(max_size, Image.LANCZOS)
                        img.save(favicon_path, 'PNG')
                    
                    favicon_updated = True
                    success = '网站图标更新成功' if not success else success
                except Exception as e:
                    error = error or f'上传网站图标时出错: {str(e)}'
    
    # 保存配置
    if not error:
        save_admin_config(admin_config)
        
        # 检查是否有设置被修改
        max_file_size_changed = original_max_file_size != admin_config.get('max_file_size')
        bg_changed = background_image_updated
        icon_changed = favicon_updated
        
        # 如果有任何设置被修改，并且启用了OneBot推送，发送设置修改通知
        if (max_file_size_changed or bg_changed or icon_changed or 
            original_onebot_push != admin_config.get('onebot_push', False) or 
            original_onebot_port != admin_config.get('onebot_port') or 
            original_onebot_group_id != admin_config.get('onebot_group_id') or 
            original_announcement != admin_config.get('announcement', '')):
            
            send_onebot_message('update_settings', 
                              max_file_size_changed=max_file_size_changed, 
                              background_changed=bg_changed, 
                              icon_changed=icon_changed)
        
    # 重新获取文件数据和设置
    check_expired_files()
    file_data = read_file_data()
    
    for code, info in file_data.items():
        expire_time = datetime.fromtimestamp(info['expire_time'])
        info['formatted_expire_time'] = expire_time.strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template('admin_panel.html', 
                          files=file_data, 
                          max_file_size=admin_config['max_file_size'], 
                          announcement=admin_config['announcement'],
                          onebot_port=admin_config.get('onebot_port', ''),
                          onebot_push=admin_config.get('onebot_push', False),
                          onebot_group_id=admin_config.get('onebot_group_id', ''),
                          error=error,
                          success=success)


    
    # 如果启用了OneBot推送，发送系统重启通知
    send_onebot_message('restart')
    
    # 返回成功响应，让前端知道重启即将开始
    response = jsonify({'success': True, 'message': '后端重启中，请稍候...'})
    
    # 在后台线程中执行重启，确保响应能够先发送给前端
    import threading
    def restart():
        # 使用os.execl实现进程重启
        python = sys.executable
        os.execl(python, python, *sys.argv)
    
    # 启动后台线程进行重启
    threading.Thread(target=restart).start()
    
    return response

# 验证取件码路由
@app.route('/verify_code')
def verify_code():
    if not check_initialized():
        return redirect(url_for('initialize'))
    
    # 获取用户IP并检查是否被拉黑
    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return abort(403, description='您的IP已被临时限制访问，请5分钟后再试')
    
    code = request.args.get('code')
    file_data = read_file_data()
    
    if code in file_data:
        # 检查文件是否过期
        current_time = datetime.now().timestamp()
        if current_time > file_data[code]['expire_time']:
            # 删除过期文件
            file_path = os.path.join(UPLOAD_FOLDER, file_data[code]['filename'])
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
            del file_data[code]
            save_file_data(file_data)
            # 记录失败尝试
            update_failed_attempts(client_ip, 'verify_code')
            return jsonify({'exists': False, 'message': '文件已过期'})
        
        # 验证成功，重置失败尝试次数
        reset_failed_attempts(client_ip, 'verify_code')
        return jsonify({
            'exists': True,
            'filename': file_data[code]['original_filename']
        })
    else:
        # 验证失败，记录失败尝试
        is_blocked = update_failed_attempts(client_ip, 'verify_code')
        if is_blocked:
            return abort(403, description='您的IP已被临时限制访问，请5分钟后再试')
        return jsonify({'exists': False, 'message': '取件码不存在'})

# 下载文件路由
@app.route('/download')
def download_file():
    if not check_initialized():
        return redirect(url_for('initialize'))
    
    # 获取用户IP并检查是否被拉黑
    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        return abort(403, description='您的IP已被临时限制访问，请5分钟后再试')
    
    # 获取更新后的防二次下载取件码
    new_code = request.args.get('new_code')
    file_data = read_file_data()
    
    if new_code in file_data:
        filename = file_data[new_code]['filename']
        original_filename = file_data[new_code]['original_filename']
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        
        # 检查文件是否存在
        if os.path.exists(file_path):
            # 发送文件供下载
            try:
                # 验证文件路径安全性
                validate_file_path(file_path)
                
                # 对中文文件名进行url编码，确保HTTP响应头正确
                encoded_filename = urllib.parse.quote(original_filename)
                
                # 下载成功，重置失败尝试次数
                reset_failed_attempts(client_ip, 'download_file')
                
                # 返回文件供下载
                return app.response_class(
                    open(file_path, 'rb').read(),
                    mimetype='application/octet-stream',
                    headers={
                        # 使用filename*参数支持UTF-8编码的文件名
                        'Content-Disposition': f'attachment; filename="{encoded_filename}"; filename*=UTF-8''{encoded_filename}',
                        'Content-Length': str(os.path.getsize(file_path))
                    }
                )
            except (ValueError, Exception) as e:
                print(f"下载文件时出错: {e}")
                # 记录失败尝试
                is_blocked = update_failed_attempts(client_ip, 'download_file')
                if is_blocked:
                    return abort(403, description='您的IP已被临时限制访问，请5分钟后再试')
                return jsonify({'success': False, 'message': '文件路径不安全或下载出错'})
        else:
            # 文件不存在，清理记录
            del file_data[new_code]
            save_file_data(file_data)
            # 记录失败尝试
            is_blocked = update_failed_attempts(client_ip, 'download_file')
            if is_blocked:
                return abort(403, description='您的IP已被临时限制访问，请5分钟后再试')
            return jsonify({'success': False, 'message': '文件不存在'})
    else:
        # 记录失败尝试
        is_blocked = update_failed_attempts(client_ip, 'download_file')
        if is_blocked:
            return abort(403, description='您的IP已被临时限制访问，请5分钟后再试')
        return jsonify({'success': False, 'message': '更新后的取件码无效'})

# 更新取件码和有效期路由
@app.route('/update_code_and_expiry', methods=['POST'])
def update_code_and_expiry():
    if not check_initialized():
        return redirect(url_for('initialize'))
    
    data = request.get_json()
    old_code = data.get('old_code')
    
    if old_code:
        file_data = read_file_data()
        if old_code in file_data:
            # 保存文件信息
            file_info = file_data[old_code]
            
            # 生成新的取件码
            new_code = str(random.randint(10000, 99999))
            while new_code in file_data:
                new_code = str(random.randint(10000, 99999))
            
            # 更新有效期为10分钟
            new_expire_time = (datetime.now() + timedelta(minutes=10)).timestamp()
            file_info['expire_time'] = new_expire_time
            file_info['expire_hours'] = 10/60  # 转换为小时
            
            # 删除旧记录，添加新记录
            del file_data[old_code]
            file_data[new_code] = file_info
            
            # 直接更新数据库（不需要重命名为取件码+文件名的格式，因为使用了随机文件名）
            save_file_data(file_data)
            
            return jsonify({'success': True, 'new_code': new_code})
        else:
            return jsonify({'success': False, 'message': '取件码不存在'})
    else:
        return jsonify({'success': False, 'message': '参数错误'})

# 获取管理员配置
@app.route('/read_admin_config', methods=['GET'])
def read_admin_config_route():
    config = read_admin_config()
    return jsonify(config)

# 获取公告内容
@app.route('/get_announcement', methods=['GET'])
def get_announcement_route():
    config = read_admin_config()
    announcement = config.get('announcement', '')
    return jsonify({'announcement': announcement})

# 测试推送路由
@app.route('/admin/test_push', methods=['POST'])
def test_push():
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': '请先登录'})
    
    try:
        # 调用send_onebot_message函数发送测试推送
        send_onebot_message('test')
        return jsonify({'success': True, 'message': '测试推送发送成功'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# 重启后端API（仅管理员可访问）
@app.route('/admin/restart_backend', methods=['POST'])
def restart_backend():
    # 检查用户是否已登录管理员账户
    if not session.get('admin_logged_in'):
        return jsonify({'success': False, 'message': '权限不足，请先登录管理员账户'})
    
    # 记录重启日志
    print(f"[{datetime.now()}] 管理员触发后端重启")
    
    # 如果启用了OneBot推送，发送系统重启通知
    send_onebot_message('restart')
    
    # 返回成功响应，让前端知道重启即将开始
    response = jsonify({'success': True, 'message': '后端重启中，请稍候...'})
    
    # 在后台线程中执行重启，确保响应能够先发送给前端
    import threading
    def restart():
        # 使用os.execl实现进程重启
        python = sys.executable
        os.execl(python, python, *sys.argv)
    
    # 启动后台线程进行重启
    threading.Thread(target=restart).start()
    
    return response

def create_template_files(template_folder):
    # initialize.html
    with open(os.path.join(template_folder, 'initialize.html'), 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>快递柜初始化</title>
    <link rel="icon" href="/css/all/icon.png" type="image/png">
    <link rel="stylesheet" href="/css/index/style.css">
    <style>
        .box {
            max-width: 400px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 16px;
            color: #333;
        }
        .form-group input {
            width: 100%;
            height: 45px;
            padding: 0 15px;
            border: 2px solid #ddd;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .form-group input:focus {
            outline: none;
            border-color: #2196F3;
        }
        .btn {
            width: 100%;
            height: 50px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .btn:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="box">
            <h2>快递柜初始化</h2>
            <form method="post">
                <div class="form-group">
                    <label for="password">设置管理员密码</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">确认</button>
            </form>
        </div>
    </div>
</body>
</html>''')
    
    # admin_login.html
    with open(os.path.join(template_folder, 'admin_login.html'), 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理员登录</title>
    <link rel="icon" href="/css/all/icon.png" type="image/png">
    <link rel="stylesheet" href="/css/index/style.css">
    <style>
        .box {
            max-width: 400px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 16px;
            color: #333;
        }
        .form-group input {
            width: 100%;
            height: 45px;
            padding: 0 15px;
            border: 2px solid #ddd;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .form-group input:focus {
            outline: none;
            border-color: #2196F3;
        }
        .btn {
            width: 100%;
            height: 50px;
            background-color: #2196F3;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .btn:hover {
            background-color: #1976D2;
        }
        .error {
            color: #f44336;
            margin-bottom: 15px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="box">
            <h2>管理员登录</h2>
            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
            <form method="post">
                <div class="form-group">
                    <label for="password">输入管理员密码</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn">登录</button>
            </form>
        </div>
    </div>
</body>
</html>''')
    
    # admin_panel.html
    with open(os.path.join(template_folder, 'admin_panel.html'), 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理员面板</title>
    <link rel="icon" href="/css/all/icon.png" type="image/png">
    <link rel="stylesheet" href="/css/index/style.css">
    <style>
        .box {
            max-width: 800px;
            width: 90%;
        }
        .logout-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            padding: 8px 16px;
            background-color: #f44336;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
            transition: background-color 0.3s ease;
        }
        .logout-btn:hover {
            background-color: #d32f2f;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: rgba(255, 255, 255, 0.5);
            font-weight: bold;
        }
        tr:hover {
            background-color: rgba(255, 255, 255, 0.3);
        }
        .action-btn {
            padding: 5px 10px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            transition: background-color 0.3s ease;
        }
        .delete-btn {
            background-color: #f44336;
            color: white;
        }
        .delete-btn:hover {
            background-color: #d32f2f;
        }
        .update-btn {
            background-color: #2196F3;
            color: white;
        }
        .update-btn:hover {
            background-color: #1976D2;
        }
        .no-files {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        .expire-form {
            display: inline-block;
        }
        .expire-select {
            padding: 3px 5px;
            border: 1px solid #ddd;
            border-radius: 3px;
            margin-right: 5px;
        }
    </style>
</head>
<body>
    <a href="{{ url_for('admin_logout') }}"><button class="logout-btn">退出登录</button></a>
    <div class="container">
        <div class="box">
            <h2>文件管理</h2>
            {% if files %}
                <table>
                    <tr>
                        <th>取件码</th>
                        <th>文件名</th>
                        <th>大小</th>
                        <th>过期时间</th>
                        <th>操作</th>
                    </tr>
                    {% for code, info in files.items() %}
                        <tr>
                            <td>{{ code }}</td>
                            <td>{{ info.original_filename }}</td>
                            <td>{{ "%.2f MB"|format(info.size / (1024 * 1024)) }}</td>
                            <td>{{ info.formatted_expire_time }}</td>
                            <td>
                                <form class="expire-form" method="post" action="{{ url_for('update_expire', code=code) }}">
                                    <select name="hours" class="expire-select">
                                        <option value="1">1小时</option>
                                        <option value="3">3小时</option>
                                        <option value="10">10小时</option>
                                        <option value="24">24小时</option>
                                    </select>
                                    <button type="submit" class="action-btn update-btn">更新</button>
                                </form>
                                <a href="{{ url_for('delete_file', code=code) }}" onclick="return confirm('确定要删除这个文件吗？');"><button class="action-btn delete-btn">删除</button></a>
                            </td>
                        </tr>
                    {% endfor %}
                </table>
            {% else %}
                <div class="no-files">暂无文件</div>
            {% endif %}
        </div>
    </div>
</body>
</html>''')
    
    # upload.html
    with open(os.path.join(template_folder, 'upload.html'), 'w', encoding='utf-8') as f:
        f.write('''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>上传文件</title>
    <link rel="icon" href="/css/all/icon.png" type="image/png">
    <link rel="stylesheet" href="/css/index/style.css">
    <style>
        .box {
            max-width: 500px;
            width: 90%;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 16px;
            color: #333;
        }
        .file-input {
            display: none;
        }
        .file-label {
            display: inline-block;
            padding: 12px 20px;
            background-color: #2196F3;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .file-label:hover {
            background-color: #1976D2;
        }
        .file-name {
            margin-left: 10px;
            color: #666;
        }
        .expire-options {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .expire-option {
            flex: 1;
            min-width: 80px;
        }
        .expire-option input[type="radio"] {
            display: none;
        }
        .expire-option label {
            display: block;
            padding: 10px;
            border: 2px solid #ddd;
            border-radius: 10px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .expire-option input[type="radio"]:checked + label {
            border-color: #2196F3;
            background-color: rgba(33, 150, 243, 0.1);
        }
        .btn {
            width: 100%;
            height: 50px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .btn:hover {
            background-color: #45a049;
        }
        .btn:disabled {
            background-color: #cccccc;
            cursor: not-allowed;
        }
        .error {
            color: #f44336;
            margin-bottom: 15px;
            text-align: center;
        }
        .success {
            color: #4CAF50;
            margin-bottom: 15px;
            text-align: center;
            padding: 15px;
            border: 2px solid #4CAF50;
            border-radius: 10px;
            background-color: rgba(76, 175, 80, 0.1);
        }
        .code-display {
            font-size: 24px;
            font-weight: bold;
            letter-spacing: 5px;
            color: #2196F3;
        }
        .progress-container {
            width: 100%;
            height: 20px;
            background-color: #f1f1f1;
            border-radius: 10px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-bar {
            height: 100%;
            background-color: #2196F3;
            width: 0%;
            transition: width 0.3s ease;
        }
        .uploading-text {
            text-align: center;
            margin-top: 10px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="box">
            <h2>上传文件</h2>
            {% if error %}
                <div class="error">{{ error }}</div>
            {% endif %}
            {% if success %}
                <div class="success">
                    <p>文件上传成功！</p>
                    <p>取件码：<span class="code-display">{{ code }}</span></p>
                    <p>请将取件码告知收件人</p>
                </div>
            {% else %}
                <form method="post" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="file">选择文件（最大50MB）</label>
                        <div>
                            <input type="file" id="file" name="file" class="file-input" required>
                            <label for="file" class="file-label">选择文件</label>
                            <span id="selected-file" class="file-name">未选择文件</span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>有效期</label>
                        <div class="expire-options">
                            <div class="expire-option">
                                <input type="radio" id="expire-1" name="expire_hours" value="1" required>
                                <label for="expire-1">1小时</label>
                            </div>
                            <div class="expire-option">
                                <input type="radio" id="expire-3" name="expire_hours" value="3">
                                <label for="expire-3">3小时</label>
                            </div>
                            <div class="expire-option">
                                <input type="radio" id="expire-10" name="expire_hours" value="10">
                                <label for="expire-10">10小时</label>
                            </div>
                            <div class="expire-option">
                                <input type="radio" id="expire-24" name="expire_hours" value="24">
                                <label for="expire-24">24小时</label>
                            </div>
                        </div>
                    </div>
                    <button type="submit" class="btn" id="upload-btn">上传文件</button>
                </form>
            {% endif %}
        </div>
    </div>
    <script>
        // 文件选择预览
        document.getElementById('file').addEventListener('change', function() {
            if (this.files.length > 0) {
                document.getElementById('selected-file').textContent = this.files[0].name;
            } else {
                document.getElementById('selected-file').textContent = '未选择文件';
            }
        });
    </script>
</body>
</html>''')

# OneBot推送函数
def send_onebot_message(message_type, **kwargs):
    """用于向OneBot发送群消息推送
       message_type: 消息类型 (upload_file, update_settings, delete_file, restart, test)
       **kwargs: 消息所需的参数
    """
    # 从配置中获取OneBot相关设置
    admin_config = read_admin_config()
    if not admin_config:
        print("OneBot推送失败: 无法读取配置")
        return
    
    # 检查推送开关是否开启
    if not admin_config.get('onebot_push', False):
        return  # 推送开关未开启，不进行推送
    
    # 获取端口号和群号
    port = admin_config.get('onebot_port')
    group_id = admin_config.get('onebot_group_id')
    
    # 验证端口和群号
    if not port or not group_id:
        print("OneBot推送失败: 未配置端口号或群号")
        return
    
    try:
        port = int(port)
        if port < 1024 or port > 65535:
            print("OneBot推送失败: 端口号无效")
            return
        
        # 验证群号格式
        if not str(group_id).isdigit():
            print("OneBot推送失败: 群号格式无效")
            return
        
        # 获取当前时间
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 根据消息类型生成不同的消息内容
        if message_type == 'upload_file':
            file_name = kwargs.get('filename', '获取失败')
            message = f"【文件快递柜】文件上传\n时间：{current_time}\n文件名：{file_name}"
        elif message_type == 'update_settings':
            max_file_size_changed = kwargs.get('max_file_size_changed', False)
            background_changed = kwargs.get('background_changed', False)
            icon_changed = kwargs.get('icon_changed', False)
            message = f"【文件快递柜】全局设置修改\n时间：{current_time}\n是否修改最大文件大小：{'是' if max_file_size_changed else '否'}\n是否修改背景图：{'是' if background_changed else '否'}\n是否修改图标：{'是' if icon_changed else '否'}"
        elif message_type == 'delete_file':
            file_name = kwargs.get('filename', '获取失败')
            message = f"【文件快递柜】管理员删除文件\n时间：{current_time}\n文件名：{file_name}"
        elif message_type == 'restart':
            message = f"【文件快递柜】系统重启\n时间：{current_time}"
        elif message_type == 'test':
            message = f"【文件快递柜】测试推送\n时间：{current_time}"
        elif message_type == 'system_start':
            message = f"【文件快递柜】系统启动\n时间：{current_time}"
        else:
            print(f"OneBot推送失败: 未知的消息类型 {message_type}")
            return
        
        # 发送推送消息
        requests.post(f'http://localhost:{port}/send_group_msg', json={
            'group_id': group_id,
            'message': [{
                'type': 'text',
                'data': {
                    'text': message
                }
            }]
        }, timeout=3)  # 添加超时设置避免请求阻塞
        
    except Exception as e:
        # 错误处理，避免影响主程序运行
        print(f"OneBot推送失败: {str(e)}")


if __name__ == '__main__':
    # 确保templates目录存在
    template_folder = os.path.join(os.path.dirname(__file__), 'templates')
    if not os.path.exists(template_folder):
        os.makedirs(template_folder)
        create_template_files(template_folder)
    
    # 发送系统启动推送
    send_onebot_message('system_start')
    
    app.run(debug=True, host='0.0.0.0', port=23478)