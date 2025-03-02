from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import requests
import os
import json
from datetime import datetime
import sys
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()


# Configuration
API_HOST = os.getenv("API_HOST", "localhost")
API_PORT = os.getenv("API_PORT", "8000")
API_BASE_URL = f"http://localhost:{API_PORT}/api"  # Use the variables
# After load_dotenv()
print(f"API_HOST: {os.getenv('API_HOST')}")
print(f"API_PORT: {os.getenv('API_PORT')}")
print(f"API_BASE_URL: {API_BASE_URL}")

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # for session and flash messages

# Add current datetime function for templates
@app.context_processor
def utility_processor():
    def now():
        return datetime.now()
    return dict(now=now)

# Template filters
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if isinstance(value, str):
        try:
            return datetime.strptime(value, '%Y-%m-%dT%H:%M:%S').strftime(format)
        except ValueError:
            return value
    return value.strftime(format) if value else ''

@app.template_filter('time_ago')
def time_ago(dt):
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
        except ValueError:
            try:
                dt = datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                return dt
    
    now = datetime.now()
    diff = now - dt
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours ago"
    elif seconds < 604800:
        return f"{int(seconds // 86400)} days ago"
    elif seconds < 2592000:
        return f"{int(seconds // 604800)} weeks ago"
    elif seconds < 31536000:
        return f"{int(seconds // 2592000)} months ago"
    else:
        return f"{int(seconds // 31536000)} years ago"

@app.template_filter('severity_class')
def severity_class(severity):
    severity = str(severity).lower()
    if severity in ('critical', '1'):
        return 'danger'
    elif severity in ('high', '2'):
        return 'danger'
    elif severity in ('medium', '3'):
        return 'warning'
    elif severity in ('low', '4'):
        return 'info'
    elif severity in ('info', '5'):
        return 'primary'
    else:
        return 'secondary'

# Routes
@app.route('/')
def index():
    """Home page with dashboard overview"""
    try:
        # Get statistics from the API
        stats_response = requests.get(f"{API_BASE_URL}/statistics")
        if stats_response.status_code == 200:
            stats = stats_response.json()
        else:
            stats = {"error": "Could not fetch statistics"}
            flash("Could not load statistics from the API", "danger")
        
        # Get recent incidents from the API
        incidents_response = requests.get(f"{API_BASE_URL}/incidents?limit=5")
        if incidents_response.status_code == 200:
            incidents = incidents_response.json().get("incidents", [])
        else:
            incidents = []
            flash("Could not load recent incidents from the API", "danger")
        
        # System status with comprehensive error handling
        try:
            system_status_response = requests.get(f"{API_BASE_URL}/system/status")
            if system_status_response.status_code == 200:
                system_status = system_status_response.json()
            else:
                # Create default status structure when API returns error
                system_status = {
                    "status": "unknown",
                    "database": {
                        "status": "unknown",
                        "type": "Unknown"
                    },
                    "server": {
                        "status": "unknown",
                        "host": API_HOST,
                        "port": API_PORT
                    },
                    "ai_models": {
                        "status": "unknown"
                    },
                    "error": f"API returned status {system_status_response.status_code}"
                }
                flash("Could not load system status from the API", "danger")
        except Exception as e:
            # Complete fallback for connection errors
            system_status = {
                "status": "error",
                "database": {"status": "unknown"},
                "server": {"status": "error", "host": API_HOST, "port": API_PORT},
                "ai_models": {"status": "unknown"},
                "error": str(e)
            }
        
        return render_template('index.html', stats=stats, incidents=incidents, system_status=system_status)
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        # Provide fallback values for all template variables
        return render_template('index.html', stats={}, incidents=[], 
                               system_status={
                                   "status": "error",
                                   "database": {"status": "unknown"},
                                   "server": {"status": "error"},
                                   "ai_models": {"status": "unknown"},
                                   "error": str(e)
                               })

@app.route('/incidents')
def incidents():
    """Page to view and manage security incidents"""
    try:
        # Get incidents from the API
        response = requests.get(f"{API_BASE_URL}/incidents")
        if response.status_code == 200:
            incidents = response.json().get("incidents", [])
        else:
            incidents = []
            flash("Could not load incidents from the API", "danger")
        
        return render_template('incidents.html', incidents=incidents)
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return render_template('incidents.html', incidents=[])

@app.route('/incident/<int:incident_id>')
def incident_detail(incident_id):
    """Page to view details of a specific incident"""
    try:
        # Get incident details from the API
        response = requests.get(f"{API_BASE_URL}/incidents/{incident_id}")
        if response.status_code == 200:
            incident = response.json()
        else:
            incident = {}
            flash("Could not load incident details from the API", "danger")
        
        # Get recommendations for the incident
        recommendations_response = requests.get(f"{API_BASE_URL}/incidents/{incident_id}/recommendations")
        if recommendations_response.status_code == 200:
            recommendations = recommendations_response.json()
        else:
            recommendations = []
            flash("Could not load recommendations from the API", "danger")
        
        return render_template('incident_detail.html', incident=incident, recommendations=recommendations)
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return render_template('incident_detail.html', incident={}, recommendations=[])

@app.route('/incidents/<int:incident_id>/resolve', methods=['POST'])
def resolve_incident(incident_id):
    """Route to mark an incident as resolved"""
    resolution_notes = request.form.get('resolution_notes', '')
    
    try:
        # Send resolution request to the API
        response = requests.post(
            f"{API_BASE_URL}/incidents/{incident_id}/resolve",
            json={'resolution_notes': resolution_notes}
        )
        
        if response.status_code == 200:
            flash("Incident marked as resolved successfully", "success")
        else:
            flash("Could not resolve the incident", "danger")
            
        return redirect(url_for('incident_detail', incident_id=incident_id))
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/incident/<int:incident_id>/resolve', methods=['GET', 'POST'])
def incident_resolve(incident_id):
    """Route to show resolve form or process resolution"""
    if request.method == 'POST':
        return resolve_incident(incident_id)
    
    # For GET requests, show a form to enter resolution notes
    return render_template('incident_resolve.html', incident_id=incident_id)

@app.route('/incident/<int:incident_id>/reopen', methods=['GET', 'POST'])
def incident_reopen(incident_id):
    """Route to reopen a resolved incident"""
    try:
        response = requests.post(f"{API_BASE_URL}/incidents/{incident_id}/reopen")
        if response.status_code == 200:
            flash("Incident reopened successfully", "success")
        else:
            flash("Could not reopen the incident", "danger")
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
    
    return redirect(url_for('incident_detail', incident_id=incident_id))

@app.route('/log-analyzer', methods=['GET', 'POST'])
def log_analyzer():
    """Page to analyze a single log entry"""
    if request.method == 'POST':
        log_data = request.form.get('log_data', '')
        source_type = request.form.get('source_type', '')
        
        try:
            # Send log data to the API for analysis
            response = requests.post(f"{API_BASE_URL}/analyze", 
                                    json={'log': log_data, 'source_type': source_type})
            if response.status_code == 200:
                analysis_results = response.json()
            else:
                analysis_results = {"error": "Could not analyze log"}
                flash("Could not analyze log using the API", "danger")
            
            return render_template('log_analyzer.html', 
                                  analysis_results=analysis_results, 
                                  log_data=log_data, 
                                  source_type=source_type)
        
        except Exception as e:
            flash(f"Error connecting to the API: {str(e)}", "danger")
            return render_template('log_analyzer.html', 
                                  analysis_results={}, 
                                  log_data=log_data, 
                                  source_type=source_type)
    
    # For GET requests, just show the form
    return render_template('log_analyzer.html', analysis_results={})

@app.route('/batch-analyzer', methods=['GET', 'POST'])
def batch_analyzer():
    """Page to submit multiple logs for batch analysis"""
    if request.method == 'POST':
        source_type = request.form.get('source_type')
        logs = []
        
        # Check if logs are provided as file
        if 'log_file' in request.files and request.files['log_file']:
            log_file = request.files['log_file']
            log_content = log_file.read().decode('utf-8')
            logs = log_content.splitlines()
        # Check if logs are provided as text
        elif 'log_text' in request.form and request.form['log_text']:
            log_content = request.form.get('log_text')
            logs = log_content.splitlines()
        else:
            flash('No logs provided', 'error')
            return render_template('batch_analyzer.html', batch_results={})
        
        try:
            # Send logs to the API for batch analysis
            response = requests.post(f"{API_BASE_URL}/analyze-batch", 
                                    json={'logs': logs, 'source_type': source_type})
            if response.status_code == 200:
                batch_results = response.json()
                return render_template('batch_analyzer.html', batch_results=batch_results)
            else:
                flash('Batch analysis failed', 'error')
                return render_template('batch_analyzer.html', batch_results={})
        
        except Exception as e:
            flash(f"Error processing logs: {str(e)}", "danger")
            return render_template('batch_analyzer.html', batch_results={})
    
    return render_template('batch_analyzer.html', batch_results={})

@app.route('/batch-analyzer/<string:job_id>')
def batch_details(job_id):
    """Page to view details of a specific batch analysis job"""
    batch_results = requests.get(f"{API_BASE_URL}/analyze/batch/jobs/{job_id}")
    
    if batch_results.status_code == 200:
        return render_template('batch_analyzer.html', batch_results=batch_results.json())
    else:
        flash('Batch analysis job not found', 'error')
        return redirect(url_for('batch_analyzer'))

@app.route('/batch-analyzer/<string:job_id>/report')
def batch_detailed_report(job_id):
    """This would be implemented to show a detailed report for a batch job
    For now, redirect to batch details"""
    return redirect(url_for('batch_details', job_id=job_id))

@app.route('/threat-intelligence', methods=['GET'])
def threat_intelligence():
    """Page to view threat intelligence data"""
    try:
        # Get statistics to show threat intelligence counts
        stats_response = requests.get(f"{API_BASE_URL}/statistics")
        threat_stats = (
            stats_response.json().get('threat_intelligence', {})
            if stats_response.status_code == 200
            else {"error": "Could not fetch threat intelligence statistics"}
        )
        if stats_response.status_code != 200:
            flash("Could not load threat intelligence statistics from the API", "danger")
        
        # Get threat intelligence data
        intel_response = requests.get(f"{API_BASE_URL}/threat-intelligence")
        intelligence = (
            intel_response.json()
            if intel_response.status_code == 200
            else {}
        )
        if intel_response.status_code != 200:
            flash("Could not load threat intelligence data from the API", "danger")
        
        # Get last update time; always provide a safe default structure
        update_response = requests.get(f"{API_BASE_URL}/threat-intelligence/status")
        if update_response.status_code == 200:
            update_json = update_response.json()
            # Ensure we always have a last_update key, even if its value is None
            ti_update = {"last_update": update_json.get("last_update", "Unknown")}
        else:
            ti_update = {"last_update": "Unknown"}
        
        return render_template('threat_intelligence.html', 
                              threat_stats=threat_stats,
                              intelligence=intelligence, 
                              ti_update=ti_update)
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return render_template('threat_intelligence.html', 
                              threat_stats={}, 
                              intelligence={}, 
                              ti_update={"last_update": "Unknown"})

@app.route('/threat-intelligence/update', methods=['POST'])
def update_threat_intelligence():
    """Route to trigger update of threat intelligence database"""
    try:
        # Send update request to the API
        response = requests.post(f"{API_BASE_URL}/threat-intelligence/update")
        
        if response.status_code == 200:
            result = response.json()
            flash(f"Successfully updated {result.get('updated', 0)} threat intelligence entries", "success")
        else:
            error_msg = response.json().get('detail', 'Unknown error occurred')
            flash(f"Failed to update threat intelligence: {error_msg}", "danger")
            
        return redirect(url_for('threat_intelligence'))
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return redirect(url_for('threat_intelligence'))

@app.route('/recommendations/<int:recommendation_id>/implement', methods=['POST'])
def implement_recommendation(recommendation_id):
    """Route to implement a specific recommendation"""
    try:
        # Get incident ID from the form
        incident_id = request.form.get('incident_id')
        
        # Send implementation request to the API
        response = requests.post(f"{API_BASE_URL}/recommendations/{recommendation_id}/implement")
        
        if response.status_code == 200:
            flash("Successfully implemented the recommendation", "success")
        else:
            flash("Could not implement the recommendation", "danger")
            
        if incident_id:
            return redirect(url_for('incident_detail', incident_id=incident_id))
        else:
            return redirect(url_for('incidents'))
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        if incident_id:
            return redirect(url_for('incident_detail', incident_id=incident_id))
        else:
            return redirect(url_for('incidents'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')