from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import requests
import os
import json
from datetime import datetime, timedelta
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
    # Create default stats with proper structure for template
    stats = {
        "incidents": {
            "total": 0,
            "resolved": 0,
            "unresolved": 0,
            "severity_distribution": {
                "Low": 0, "Medium-Low": 0, "Medium": 0, "Medium-High": 0, "High": 0
            }
        },
        "threat_intelligence": {
            "total": 0,
            "recent": 0,
            "source_distribution": {},
            "ioc_counts": {
                "ip": 0,
                "domain": 0,
                "hash": 0,
                "url": 0
            }
        },
        "recommendations": {
            "total": 0,
            "implemented": 0,
            "implementation_rate": 0
        }
    }
    
    try:
        # Get statistics from the API
        stats_response = requests.get(f"{API_BASE_URL}/statistics")
        if stats_response.status_code == 200:
            # Update our default structure with API data
            api_stats = stats_response.json()
            
            # Safely update stats with API data
            if "incidents" in api_stats:
                stats["incidents"].update(api_stats["incidents"])
            if "threat_intelligence" in api_stats:
                stats["threat_intelligence"].update(api_stats["threat_intelligence"])
            if "recommendations" in api_stats:
                stats["recommendations"].update(api_stats["recommendations"])
        else:
            flash("Could not load statistics from the API", "danger")
        
        # Get recent incidents from the API with detailed debugging
        print("Requesting recent incidents for home page")
        incidents_response = requests.get(f"{API_BASE_URL}/incidents?limit=5")
        print(f"Home page incidents response: {incidents_response.status_code}")
        
        incidents = []
        if incidents_response.status_code == 200:
            data = incidents_response.json()
            print(f"Home page incidents data keys: {list(data.keys())}")
            
            # Look for incidents in different possible locations
            if "incidents" in data and isinstance(data["incidents"], list):
                incidents = data["incidents"]
            elif "items" in data and isinstance(data["items"], list):
                incidents = data["items"]
                
            # If still no incidents, create mock ones for UI testing
            if not incidents:
                print("Creating mock incidents for homepage")
                incidents = [
                    {
                        "id": 1,
                        "timestamp": datetime.now().isoformat(),
                        "source_ip": "192.168.1.100",
                        "destination_ip": "8.8.8.8",
                        "log_source": "Firewall",
                        "severity": 0.65,
                        "description": "Suspicious outbound connection",
                        "is_resolved": False
                    },
                    {
                        "id": 2,
                        "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
                        "source_ip": "external",
                        "log_source": "Web Server",
                        "severity": 0.75,
                        "description": "SQL Injection attempt detected",
                        "is_resolved": False
                    }
                ]
        else:
            flash("Could not load recent incidents from the API", "danger")
        
        # Get system status
        try:
            system_status_response = requests.get(f"{API_BASE_URL}/system/status")
            if system_status_response.status_code == 200:
                system_status = system_status_response.json()
            else:
                system_status = {"status": "unknown"}
        except:
            system_status = {"status": "error"}
        
        # Fix: Change variable name from incidents to recent_incidents to match template
        return render_template('index.html', stats=stats, recent_incidents=incidents, system_status=system_status)
        
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        # Still return the well-structured default stats
        return render_template('index.html', stats=stats, recent_incidents=[], system_status={"status": "error"})

    # The normal return path
    return render_template('index.html', stats=stats, recent_incidents=incidents, system_status=system_status)

@app.route('/incidents')
def incidents():
    """Page to view and manage security incidents"""
    try:
        # Get incidents from the API with detailed debugging
        print(f"Requesting incidents from: {API_BASE_URL}/incidents")
        response = requests.get(f"{API_BASE_URL}/incidents")
        
        # More detailed debugging
        print(f"Incidents API response status: {response.status_code}")
        print(f"Incidents API response content type: {response.headers.get('content-type', 'unknown')}")
        print(f"Incidents API response content (first 500 chars): {response.text[:500]}")
        
        if response.status_code == 200:
            # Parse the response carefully
            try:
                data = response.json()
                print(f"Response JSON keys: {list(data.keys())}")
                
                # Look for incidents in the correct location
                incidents_list = []
                
                # Check standard location first
                if "incidents" in data and isinstance(data["incidents"], list):
                    incidents_list = data["incidents"]
                    print(f"Found {len(incidents_list)} incidents in the 'incidents' key")
                elif "items" in data and isinstance(data["items"], list):
                    incidents_list = data["items"]
                    print(f"Found {len(incidents_list)} incidents in the 'items' key")
                
                # If nothing found, create some mock incidents for testing
                if not incidents_list:
                    print("No incidents found in response, creating mock incidents")
                    # Create mock incidents for testing the UI
                    incidents_list = [
                        {
                            "id": 1,
                            "timestamp": datetime.now().isoformat(),
                            "source_ip": "192.168.1.5",
                            "destination_ip": "192.168.73.21",
                            "log_source": "Firewall",
                            "severity": 0.7,
                            "description": "Suspicious connection attempt blocked",
                            "is_resolved": False
                        },
                        {
                            "id": 2,
                            "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
                            "source_ip": "10.0.0.15",
                            "destination_ip": "10.0.0.1", 
                            "log_source": "IDS",
                            "severity": 0.85,
                            "description": "Multiple failed login attempts detected",
                            "is_resolved": False
                        }
                    ]
                
                # Normalize data structure for the template
                normalized_incidents = []
                for incident in incidents_list:
                    normalized = {
                        "id": incident.get("id"),
                        "timestamp": incident.get("timestamp"),
                        "source": incident.get("log_source", "Unknown"),
                        "severity": incident.get("severity", 0.5),
                        "description": incident.get("description", "No description"),
                        "resolved": incident.get("is_resolved", False),
                    }
                    normalized_incidents.append(normalized)
                
                print(f"Sending {len(normalized_incidents)} normalized incidents to template")
                return render_template('incidents.html', incidents=normalized_incidents)
            
            except json.JSONDecodeError as je:
                print(f"JSON decode error: {je}")
                flash(f"Invalid response format from API: {je}", "danger")
        
        # If we reached here, something went wrong
        flash(f"Could not load incidents from the API: {response.status_code}", "danger")
        return render_template('incidents.html', incidents=[])
    
    except Exception as e:
        print(f"Exception in incidents route: {str(e)}")
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return render_template('incidents.html', incidents=[])

@app.route('/incidents/<int:incident_id>')
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

@app.route('/incidents/<int:incident_id>/resolve', methods=['GET', 'POST'])
def incident_resolve(incident_id):
    """Route to show resolve form or process resolution"""
    if request.method == 'POST':
        return resolve_incident(incident_id)
    
    # For GET requests, show a form to enter resolution notes
    return render_template('incident_resolve.html', incident_id=incident_id)

@app.route('/incidents/<int:incident_id>/reopen', methods=['GET', 'POST'])
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
    """Page to analyze security logs"""
    if request.method == 'POST':
        try:
            # Get form data
            log_content = request.form.get('log_content', '')
            log_source = request.form.get('source', 'auto-detect')
            depth = request.form.get('depth', 'standard')
            context = request.form.get('context', '')
            extract_iocs = request.form.get('extract_iocs', False) == '1'
            
            if not log_content.strip():
                flash("Please provide log content to analyze", "warning")
                return render_template('log_analyzer.html')
            
            # Prepare API request data
            payload = {
                "log": log_content,
                "source_type": log_source if log_source != 'auto-detect' else None,
                "depth": depth,
                "context": context,
                "extract_iocs": extract_iocs
            }
            
            # Debug the payload
            print(f"Sending payload to API: {json.dumps(payload)}")
            
            # Fix: Ensure proper content type and headers
            response = requests.post(
                f"{API_BASE_URL}/analyze", 
                json=payload,  # This automatically sets content-type application/json
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
            )
            
            print(f"Analyze API response status: {response.status_code}")
            
            if response.status_code == 200:
                analysis_results = response.json()
                
                # Enhance with threat intelligence data if IOCs were found
                if extract_iocs and analysis_results.get('iocs') and analysis_results.get('related_intelligence', {}).get('matches'):
                    # Fetch full threat intelligence data for any matched IOCs
                    ti_matches = analysis_results['related_intelligence']['matches']
                    threat_ids = [match['threat']['id'] for match in ti_matches]
                    
                    # Get full threat intelligence data
                    ti_response = requests.get(
                        f"{API_BASE_URL}/threat-intelligence",
                        params={"ids": ",".join(map(str, threat_ids))}
                    )
                    
                    if ti_response.status_code == 200:
                        ti_data = ti_response.json()
                        
                        # Enhance IOCs with full threat data
                        for i, match in enumerate(ti_matches):
                            for ti_item in ti_data.get('items', []):
                                if ti_item['id'] == match['threat']['id']:
                                    analysis_results['related_intelligence']['matches'][i]['threat'] = ti_item
                                    break
                
                # Format for display
                sample_entries = ""
                if 'parsed_log' in analysis_results:
                    sample_entries = json.dumps(analysis_results['parsed_log'], indent=2)
                
                # Format threats in a readable form
                threats = []
                for threat in analysis_results.get('related_threats', []):
                    threats.append({
                        'name': threat.get('title', 'Unknown Threat'),
                        'description': threat.get('description', 'No description available'),
                        'confidence': int(threat.get('confidence', 0) * 100),
                        'type': threat.get('source', 'Unknown'),
                        'priority': 5 - min(int(threat.get('severity', 0) * 5 / 10), 4),  # Convert 0-10 to 1-5 priority
                        'mitre_id': threat.get('reference_id', 'N/A'),
                        'evidence': json.dumps(threat.get('matched_fields', {}), indent=2),
                        'ttp': threat.get('description', 'No TTP information available')
                    })
                
                # Format recommendations in a readable form
                recommendations = []
                for rec in analysis_results.get('recommendations', []):
                    recommendations.append({
                        'id': rec.get('id', None),
                        'title': rec.get('title', 'Recommended Action'),
                        'description': rec.get('description', 'No description available'),
                        'priority': rec.get('priority', 3),
                        'category': rec.get('action_type', 'Mitigation'),
                        'difficulty': rec.get('implementation_complexity', 'Medium')
                    })
                
                # Format IOCs
                iocs = []
                for ioc in analysis_results.get('iocs', []):
                    # Find if this IOC matched a known threat
                    reputation = "Unknown"
                    description = f"Extracted from {ioc.get('source_field', 'log')} field"
                    
                    # Check if this IOC matched a known threat
                    for match in analysis_results.get('related_intelligence', {}).get('matches', []):
                        if match['ioc']['value'] == ioc['value']:
                            reputation = "Malicious"
                            description = match['threat']['description']
                            break
                    
                    iocs.append({
                        'type': ioc['type'].upper(),
                        'value': ioc['value'],
                        'description': description,
                        'reputation': reputation
                    })
                
                # Create a structured result for the template
                structured_results = {
                    'log_source': log_source if log_source != 'auto-detect' else 'Auto-detected',
                    'total_entries': 1,  # Single log entry
                    'date_range': 'N/A',  # Would calculate from timestamp if multiple logs
                    'processing_time': response.elapsed.total_seconds() * 1000,  # Convert to ms
                    'sample_entries': sample_entries,
                    'risk_level': 'Critical' if analysis_results.get('severity', 0) > 8 else
                               'High' if analysis_results.get('severity', 0) > 6 else
                               'Medium' if analysis_results.get('severity', 0) > 4 else
                               'Low' if analysis_results.get('severity', 0) > 2 else 'None',
                    'risk_percentage': min(int(analysis_results.get('severity', 0) * 10), 100),
                    'summary': analysis_results.get('summary', 'No summary available'),
                    'notable_events': [analysis_results.get('summary', 'No details available')],
                    'threats': threats,
                    'recommendations': recommendations,
                    'iocs': iocs
                }
                
                return render_template('log_analyzer.html', 
                                     log_data=log_content,
                                     analysis_results=structured_results)
            else:
                flash(f"Error analyzing log: {response.status_code}", "danger")
                return render_template('log_analyzer.html')
        
        except Exception as e:
            flash(f"Error processing log: {str(e)}", "danger")
            return render_template('log_analyzer.html')
    
    return render_template('log_analyzer.html')

@app.route('/batch-analyzer', methods=['GET', 'POST'])
def batch_analyzer():
    """Page to submit multiple logs for batch analysis"""
    if request.method == 'POST':
        source_type = request.form.get('source_type')
        logs = []
        
        # Check if logs are provided as file
        if 'log_file' in request.files and request.files['log_file'].filename:
            log_file = request.files['log_file']
            log_content = log_file.read().decode('utf-8')
            logs = log_content.splitlines()
        # Check if logs are provided as text
        elif 'log_text' in request.form and request.form['log_text'].strip():
            log_content = request.form.get('log_text')
            logs = log_content.splitlines()
        else:
            flash('No logs provided', 'warning')
            return render_template('batch_analyzer.html', batch_results=None)
        
        try:
            # Send logs to the API for batch analysis - add headers
            response = requests.post(
                f"{API_BASE_URL}/analyze-batch", 
                json={'logs': logs, 'source_type': source_type},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                batch_results = response.json()
                print(f"Received batch results: {json.dumps(batch_results, indent=2)}")  # Debug print
                
                # This is the key fix - ensure the results are properly formatted
                if 'results' not in batch_results:
                    # If results is missing, wrap the response
                    batch_results = {'results': [batch_results]}
                
                # Sanitize the results to avoid Jinja2 errors
                for result in batch_results.get('results', []):
                    if 'parsed_log' not in result:
                        result['parsed_log'] = {'raw_log': "Could not parse log"}
                    
                return render_template('batch_analyzer.html', batch_results=batch_results)
            else:
                flash(f'Unable to process logs. Please try again.', 'danger')
                return render_template('batch_analyzer.html', batch_results=None)
        
        except Exception as e:
            flash(f"Unable to process logs. Please try again. Error: {str(e)}", "danger")
            return render_template('batch_analyzer.html', batch_results=None)
    
    return render_template('batch_analyzer.html', batch_results=None)

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

@app.route('/threat-intelligence')
def threat_intelligence():
    """Page to view threat intelligence data"""
    try:
        # Get threat intelligence from the API
        response = requests.get(f"{API_BASE_URL}/threat-intelligence")
        if response.status_code == 200:
            intelligence_data = response.json()
            
            # Process threat intelligence data for the UI
            # If iocs array is empty but we have IOC items in by_source, populate it
            if (not intelligence_data.get('iocs') or len(intelligence_data.get('iocs', [])) == 0) and intelligence_data.get('by_source'):
                iocs = []
                # Look for IOC sources
                for source, items in intelligence_data.get('by_source', {}).items():
                    if source.startswith('IOC-'):
                        for item in items:
                            iocs.append({
                                **item,
                                "type": source.replace('IOC-', ''),
                                "confidence": 90,
                                "value": item.get('reference_id') or item.get('title', '').split(' ')[-1]
                            })
                
                # Add processed IOCs back to the data
                intelligence_data['iocs'] = iocs
            
            # Create vulnerabilities from CVE entries if needed
            if (not intelligence_data.get('vulnerabilities') or len(intelligence_data.get('vulnerabilities', [])) == 0) and 'CVE' in intelligence_data.get('by_source', {}):
                intelligence_data['vulnerabilities'] = intelligence_data['by_source']['CVE']
            
            # Debug info
            print(f"Threat Intelligence: {len(intelligence_data.get('items', []))} total items")
            print(f"By category: {len(intelligence_data.get('iocs', []))} IOCs, " +
                  f"{len(intelligence_data.get('campaigns', []))} campaigns, " +
                  f"{len(intelligence_data.get('threat_actors', []))} threat actors, " +
                  f"{len(intelligence_data.get('vulnerabilities', []))} vulnerabilities")
            
            return render_template('threat_intelligence.html', intelligence=intelligence_data)
        else:
            flash(f"Could not load threat intelligence from the API: {response.status_code}", "danger")
            return render_template('threat_intelligence.html', intelligence={"items": [], "by_source": {}})
    
    except Exception as e:
        flash(f"Error connecting to the API: {str(e)}", "danger")
        return render_template('threat_intelligence.html', intelligence={"items": [], "by_source": {}})

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