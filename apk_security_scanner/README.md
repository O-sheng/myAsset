# APK Security Scanner

一个基于 Python 的 Android APK 安全扫描工具，提供美观的 HTML 安全测试报告。

## 功能特点

- 📱 **APK 文件上传**: 支持拖拽上传或直接选择 APK 文件
- 🔍 **安全分析**: 
  - 权限分析（危险权限检测）
  - 组件分析（Activities, Services, Receivers, Providers）
  - 风险评分
- 📊 **美观报告**: 生成专业的 HTML 格式安全测试报告
- 🎨 **现代化 UI**: 响应式设计，支持桌面和移动端

## 安装步骤

### 1. 安装依赖

```bash
cd apk_security_scanner
pip install -r requirements.txt
```

### 2. 运行应用

```bash
python app.py
```

应用将在 `http://localhost:5000` 启动。

## 使用方法

1. 打开浏览器访问 `http://localhost:5000`
2. 上传 APK 文件（支持拖拽或点击选择）
3. 点击"Analyze APK"按钮开始分析
4. 查看生成的安全测试报告
5. 在"Reports"页面查看所有历史报告

## 项目结构

```
apk_security_scanner/
├── app.py                 # 主应用程序
├── requirements.txt       # Python 依赖
├── templates/            # HTML 模板
│   ├── index.html        # 主页（上传页面）
│   └── reports.html      # 报告列表页面
├── uploads/              # 上传的 APK 文件存储目录
└── reports/              # 生成的报告存储目录
```

## 安全检测项

### 权限检测
检测以下危险权限：
- 联系人相关权限
- 短信相关权限
- 通话相关权限
- 位置信息权限
- 相机和麦克风权限
- 存储权限
- 系统级权限等

### 组件分析
- Activities（活动）
- Services（服务）
- Broadcast Receivers（广播接收器）
- Content Providers（内容提供者）

### 风险评分
根据检测到的安全问题自动计算风险评分（0-100）：
- **Low (0-25)**: 绿色
- **Medium (26-50)**: 黄色
- **High (51-75)**: 橙色
- **Critical (76-100)**: 红色

## 技术栈

- **后端**: Flask + Androguard
- **前端**: HTML5 + CSS3 + JavaScript
- **分析引擎**: Androguard（Android 逆向工程工具）

## 注意事项

1. 生产环境请修改 `app.secret_key`
2. 建议配置适当的文件大小限制
3. 定期清理 uploads 和 reports 目录
4. 此工具仅供安全研究和测试使用

## 许可证

MIT License
