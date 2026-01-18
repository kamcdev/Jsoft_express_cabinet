let maxFileSizeMB = 50; // 默认值

// 页面加载时获取最大文件大小设置
document.addEventListener('DOMContentLoaded', function() {
    fetch('/get_max_file_size')
        .then(response => response.json())
        .then(data => {
            if (data && data.max_file_size) {
                maxFileSizeMB = data.max_file_size;
                document.getElementById('max-size-display').textContent = maxFileSizeMB;
            }
        })
        .catch(error => {
            console.error('获取文件大小设置失败:', error);
        });
});

// 文件选择预览和大小校验
document.getElementById('file').addEventListener('change', function() {
    const fileSizeError = document.getElementById('file-size-error');
    const uploadBtn = document.getElementById('upload-btn');
    
    if (this.files.length > 0) {
        const file = this.files[0];
        const fileSizeMB = file.size / (1024 * 1024);
        
        document.getElementById('selected-file').textContent = `${file.name} (${fileSizeMB.toFixed(2)}MB)`;
        
        // 前端文件大小校验
        if (fileSizeMB > maxFileSizeMB) {
            fileSizeError.textContent = `文件大小超过限制！最大允许 ${maxFileSizeMB}MB，当前文件 ${fileSizeMB.toFixed(2)}MB`;
            fileSizeError.style.display = 'block';
            uploadBtn.disabled = true;
        } else {
            fileSizeError.style.display = 'none';
            uploadBtn.disabled = false;
        }
    } else {
        document.getElementById('selected-file').textContent = '未选择文件';
        fileSizeError.style.display = 'none';
        uploadBtn.disabled = false;
    }
});