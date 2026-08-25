from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
import os
import zipfile
import hashlib
from datetime import datetime
from androguard.core.apk import APK

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORT_FOLDER'] = 'reports'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

ALLOWED_EXTENSIONS = {'apk'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_md5(filepath):
    """Calculate MD5 hash of file"""
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def analyze_apk(filepath):
    """Perform security analysis on APK file"""
    results = {
        'filename': os.path.basename(filepath),
        'md5': calculate_md5(filepath),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'basic_info': {},
        'permissions': [],
        'dangerous_permissions': [],
        'components': {},
        'security_issues': [],
        'risk_score': 0
    }
    
    try:
        apk = APK(filepath)
        
        # Basic Info
        results['basic_info'] = {
            'package_name': apk.get_package(),
            'app_name': apk.get_app_name(),
            'version_name': apk.get_androidversion_name(),
            'version_code': apk.get_androidversion_code(),
            'min_sdk_version': apk.get_min_sdk_version(),
            'target_sdk_version': apk.get_target_sdk_version(),
            'num_activities': len(apk.get_activities()),
            'num_services': len(apk.get_services()),
            'num_receivers': len(apk.get_receivers()),
            'num_providers': len(apk.get_providers())
        }
        
        # Permissions Analysis
        all_permissions = apk.get_permissions()
        dangerous_perms = [
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_SMS',
            'android.permission.WRITE_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.CALL_PHONE',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.PROCESS_OUTGOING_CALLS',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.DEVICE_POWER',
            'android.permission.DISABLE_KEYGUARD',
            'android.permission.WAKE_LOCK',
            'android.permission.GET_ACCOUNTS',
            'android.permission.USE_CREDENTIALS',
            'android.permission.MANAGE_ACCOUNTS',
            'android.permission.AUTHENTICATE_ACCOUNTS',
            'android.permission.INTERACT_ACROSS_USERS_FULL',
            'android.permission.INSTALL_PACKAGES',
            'android.permission.DELETE_PACKAGES',
            'android.permission.CLEAR_APP_CACHE',
            'android.permission.MOVE_PACKAGE',
            'android.permission.CHANGE_COMPONENT_ENABLED_STATE',
            'android.permission.PERSISTENT_ACTIVITY',
            'android.permission.SET_PREFERRED_APPLICATIONS',
            'android.permission.BROADCAST_SMS',
            'android.permission.BROADCAST_WAP_PUSH',
            'android.permission.READ_PRECISE_PHONE_STATE',
            'android.permission.USE_SIP',
            'android.permission.BODY_SENSORS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.ACCEPT_HANDOVER',
            'android.permission.ACTIVITY_RECOGNITION',
            'android.permission.ANSWER_PHONE_CALLS',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.ACCESS_BACKGROUND_LOCATION',
            'android.permission.ACCESS_MEDIA_LOCATION',
            'android.permission.FOREGROUND_SERVICE',
            'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
            'android.permission.SYSTEM_OVERLAY_WINDOW',
            'android.permission.WRITE_SETTINGS',
            'android.permission.WRITE_SECURE_SETTINGS'
        ]
        
        for perm in all_permissions:
            perm_info = {
                'name': perm,
                'is_dangerous': perm in dangerous_perms
            }
            results['permissions'].append(perm_info)
            if perm in dangerous_perms:
                results['dangerous_permissions'].append(perm)
                results['security_issues'].append({
                    'severity': 'high' if perm in ['android.permission.SYSTEM_ALERT_WINDOW', 
                                                    'android.permission.REQUEST_INSTALL_PACKAGES',
                                                    'android.permission.BIND_DEVICE_ADMIN'] else 'medium',
                    'category': 'Permission',
                    'issue': f'Dangerous permission: {perm}',
                    'recommendation': f'Review if {perm} is necessary. Consider requesting at runtime.'
                })
        
        # Component Analysis
        activities = apk.get_activities()
        services = apk.get_services()
        receivers = apk.get_receivers()
        providers = apk.get_providers()
        
        results['components'] = {
            'activities': activities,
            'services': services,
            'receivers': receivers,
            'providers': providers
        }
        
        # Check for exported components (potential security issues)
        # Note: This is a simplified check - real analysis would need to parse AndroidManifest.xml more thoroughly
        
        # Calculate risk score
        risk_score = 0
        risk_score += len(results['dangerous_permissions']) * 5
        risk_score += len([p for p in results['dangerous_permissions'] if p in ['android.permission.SYSTEM_ALERT_WINDOW', 
                                                                                'android.permission.REQUEST_INSTALL_PACKAGES',
                                                                                'android.permission.BIND_DEVICE_ADMIN']]) * 10
        
        # Cap risk score at 100
        results['risk_score'] = min(risk_score, 100)
        
        # Add general security recommendations
        if results['risk_score'] > 50:
            results['security_issues'].append({
                'severity': 'high',
                'category': 'General',
                'issue': 'High overall risk score',
                'recommendation': 'Conduct thorough security review before deployment'
            })
        
    except Exception as e:
        results['error'] = str(e)
        results['security_issues'].append({
            'severity': 'critical',
            'category': 'Analysis Error',
            'issue': f'Failed to analyze APK: {str(e)}',
            'recommendation': 'Ensure the APK file is valid and not corrupted'
        })
    
    return results

def generate_html_report(results, report_path):
    """Generate HTML security report"""
    
    risk_level = 'Low'
    risk_color = '#28a745'
    if results['risk_score'] > 75:
        risk_level = 'Critical'
        risk_color = '#dc3545'
    elif results['risk_score'] > 50:
        risk_level = 'High'
        risk_color = '#fd7e14'
    elif results['risk_score'] > 25:
        risk_level = 'Medium'
        risk_color = '#ffc107'
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK Security Report - {results['filename']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            display: inline-block;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }}
        
        .info-card h3 {{
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.2em;
        }}
        
        .info-card p {{
            color: #666;
            font-size: 0.95em;
        }}
        
        .risk-score {{
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 15px;
            margin-bottom: 30px;
        }}
        
        .score-circle {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: {risk_color};
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 3em;
            font-weight: bold;
            margin: 0 auto 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        
        .risk-level {{
            font-size: 1.5em;
            color: {risk_color};
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .issues-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        .issues-table th,
        .issues-table td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .issues-table th {{
            background: #2c3e50;
            color: white;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        
        .issues-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}
        
        .permission-list {{
            list-style: none;
        }}
        
        .permission-item {{
            padding: 10px 15px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 3px solid #dee2e6;
        }}
        
        .permission-item.dangerous {{
            border-left-color: #dc3545;
            background: #fff5f5;
        }}
        
        .permission-item.safe {{
            border-left-color: #28a745;
        }}
        
        .component-section {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        
        .component-section h4 {{
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        
        .component-count {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 3px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            margin-left: 10px;
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 30px;
            margin-top: 40px;
        }}
        
        .footer p {{
            opacity: 0.8;
        }}
        
        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2em;
            }}
            
            .content {{
                padding: 20px;
            }}
            
            .info-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 APK Security Analysis Report</h1>
            <p>Comprehensive Security Assessment</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2 class="section-title">Executive Summary</h2>
                <div class="risk-score">
                    <div class="score-circle">{results['risk_score']}</div>
                    <div class="risk-level">Risk Level: {risk_level}</div>
                    <p style="margin-top: 15px; color: #666;">Based on permissions, components, and security configurations</p>
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">Basic Information</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <h3>📱 Application Details</h3>
                        <p><strong>Package Name:</strong> {results['basic_info'].get('package_name', 'N/A')}</p>
                        <p><strong>App Name:</strong> {results['basic_info'].get('app_name', 'N/A')}</p>
                        <p><strong>Version:</strong> {results['basic_info'].get('version_name', 'N/A')} ({results['basic_info'].get('version_code', 'N/A')})</p>
                    </div>
                    <div class="info-card">
                        <h3>🔐 File Information</h3>
                        <p><strong>Filename:</strong> {results['filename']}</p>
                        <p><strong>MD5 Hash:</strong> {results['md5']}</p>
                        <p><strong>Analysis Date:</strong> {results['timestamp']}</p>
                    </div>
                    <div class="info-card">
                        <h3>📊 SDK Information</h3>
                        <p><strong>Min SDK:</strong> {results['basic_info'].get('min_sdk_version', 'N/A')}</p>
                        <p><strong>Target SDK:</strong> {results['basic_info'].get('target_sdk_version', 'N/A')}</p>
                    </div>
                    <div class="info-card">
                        <h3>🏗️ Components Overview</h3>
                        <p><strong>Activities:</strong> {results['basic_info'].get('num_activities', 0)}</p>
                        <p><strong>Services:</strong> {results['basic_info'].get('num_services', 0)}</p>
                        <p><strong>Receivers:</strong> {results['basic_info'].get('num_receivers', 0)}</p>
                        <p><strong>Providers:</strong> {results['basic_info'].get('num_providers', 0)}</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2 class="section-title">Security Issues ({len(results['security_issues'])})</h2>
                {generate_issues_table(results['security_issues']) if results['security_issues'] else '<p style="color: #28a745; font-size: 1.2em;">✅ No significant security issues detected!</p>'}
            </div>
            
            <div class="section">
                <h2 class="section-title">Permissions Analysis</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <h3>Total Permissions</h3>
                        <p style="font-size: 2em; color: #667eea; font-weight: bold;">{len(results['permissions'])}</p>
                    </div>
                    <div class="info-card">
                        <h3>Dangerous Permissions</h3>
                        <p style="font-size: 2em; color: #dc3545; font-weight: bold;">{len(results['dangerous_permissions'])}</p>
                    </div>
                </div>
                
                <h3 style="margin: 30px 0 20px; color: #2c3e50;">All Permissions</h3>
                <ul class="permission-list">
                    {generate_permission_list(results['permissions'])}
                </ul>
            </div>
            
            <div class="section">
                <h2 class="section-title">Application Components</h2>
                
                <div class="component-section">
                    <h4>Activities <span class="component-count">{len(results['components'].get('activities', []))}</span></h4>
                    {generate_component_list(results['components'].get('activities', []))}
                </div>
                
                <div class="component-section">
                    <h4>Services <span class="component-count">{len(results['components'].get('services', []))}</span></h4>
                    {generate_component_list(results['components'].get('services', []))}
                </div>
                
                <div class="component-section">
                    <h4>Broadcast Receivers <span class="component-count">{len(results['components'].get('receivers', []))}</span></h4>
                    {generate_component_list(results['components'].get('receivers', []))}
                </div>
                
                <div class="component-section">
                    <h4>Content Providers <span class="component-count">{len(results['components'].get('providers', []))}</span></h4>
                    {generate_component_list(results['components'].get('providers', []))}
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by APK Security Scanner</p>
            <p style="margin-top: 10px; font-size: 0.9em;">This report is generated automatically and should be reviewed by security professionals</p>
        </div>
    </div>
</body>
</html>'''
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def generate_issues_table(issues):
    """Generate HTML table for security issues"""
    if not issues:
        return ''
    
    html = '''<table class="issues-table">
        <thead>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Issue</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>'''
    
    for issue in issues:
        severity_class = f"severity-{issue['severity']}"
        html += f'''
            <tr>
                <td><span class="severity-badge {severity_class}">{issue['severity']}</span></td>
                <td>{issue['category']}</td>
                <td>{issue['issue']}</td>
                <td>{issue['recommendation']}</td>
            </tr>'''
    
    html += '''
        </tbody>
    </table>'''
    
    return html

def generate_permission_list(permissions):
    """Generate HTML list for permissions"""
    html = ''
    for perm in permissions:
        css_class = 'dangerous' if perm['is_dangerous'] else 'safe'
        icon = '⚠️' if perm['is_dangerous'] else '✅'
        html += f'<li class="permission-item {css_class}">{icon} {perm["name"]}</li>\n'
    return html

def generate_component_list(components):
    """Generate HTML list for components"""
    if not components:
        return '<p style="color: #999;">No components found</p>'
    
    html = '<ul style="list-style: none; padding-left: 0;">'
    for comp in components[:20]:  # Limit to first 20 for readability
        html += f'<li style="padding: 8px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 0.9em;">📦 {comp}</li>'
    
    if len(components) > 20:
        html += f'<li style="padding: 8px 0; color: #999; font-style: italic;">... and {len(components) - 20} more</li>'
    
    html += '</ul>'
    return html

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        # Save uploaded file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze APK
        results = analyze_apk(filepath)
        
        # Generate report
        report_filename = f"report_{timestamp}.html"
        report_path = os.path.join(app.config['REPORT_FOLDER'], report_filename)
        generate_html_report(results, report_path)
        
        flash('APK analyzed successfully!')
        return redirect(url_for('view_report', report_name=report_filename))
    
    flash('Invalid file type. Please upload an APK file.')
    return redirect(request.url)

@app.route('/report/<report_name>')
def view_report(report_name):
    return send_from_directory(app.config['REPORT_FOLDER'], report_name)

@app.route('/reports')
def list_reports():
    reports = []
    for filename in os.listdir(app.config['REPORT_FOLDER']):
        if filename.endswith('.html'):
            filepath = os.path.join(app.config['REPORT_FOLDER'], filename)
            reports.append({
                'name': filename,
                'created': datetime.fromtimestamp(os.path.getctime(filepath)).strftime('%Y-%m-%d %H:%M:%S')
            })
    reports.sort(key=lambda x: x['created'], reverse=True)
    return render_template('reports.html', reports=reports)

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
    
    app.run(debug=False, host='0.0.0.0', port=5000)
