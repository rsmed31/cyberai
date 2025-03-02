# CyberAI Web Interface

This is the web interface for the AI-Powered Cybersecurity Incident Response Assistant. It provides a user-friendly way to interact with the backend API for analyzing security logs, managing incidents, and accessing threat intelligence.

## Overview

The web interface is built with Flask and provides the following features:

- Dashboard with key security metrics and recent incidents
- Log analyzer for manual log analysis
- Batch analyzer for processing multiple log files
- Incident management with detailed views and resolution tools
- Threat intelligence database access
- Security recommendations tracking

## Setup and Installation

### Prerequisites

- Python 3.8 or higher
- Access to the CyberAI backend API
- Required Python packages listed in the project's `requirements.txt`

### Configuration

The web interface uses environment variables for configuration. You can set these in a `.env` file in the project root or through your system environment.

Required environment variables:

- `API_HOST`: The hostname of the backend API (default: localhost)
- `API_PORT`: The port of the backend API (default: 8000)
- `FLASK_SECRET_KEY`: Secret key for Flask sessions
- `FLASK_PORT`: Port to run the Flask web server on (default: 5000)

### Running the Web Interface

1. Ensure the backend API is running and accessible
2. Navigate to the project root directory
3. Run the Flask application:

```bash
# From the project root
python web/app.py

# Or directly from the web directory
cd web
python app.py
```

The web interface will be available at `http://localhost:5000` (or the port specified in your environment).

## Project Structure

- `app.py`: Main Flask application file
- `templates/`: HTML templates for the web interface
  - `base.html`: Base template with common layout elements
  - `index.html`: Dashboard template
  - `log_analyzer.html`: Log analysis page
  - `batch_analyzer.html`: Batch log analysis page
  - `incidents.html`: Incident listing page
  - `incident_detail.html`: Detailed incident view
  - `threat_intelligence.html`: Threat intelligence page
- `static/`: Static files for the web interface
  - `css/`: CSS stylesheets
  - `js/`: JavaScript files
  - `img/`: Images and icons

## Development

### Adding New Features

When adding new features to the web interface:

1. Create a new route in `app.py`
2. Create a corresponding template in the `templates/` directory
3. Add any necessary static assets
4. Update navigation links in the `base.html` template

### API Integration

The web interface communicates with the backend API through the `api_request` helper function in `app.py`. Use this function to make requests to the API endpoints.

Example:

```python
# Fetch data from the API
data = api_request('/api/endpoint', method='GET')

# Send data to the API
response = api_request('/api/endpoint', method='POST', data={'key': 'value'})
```

## Troubleshooting

Common issues:

- **Cannot connect to API**: Ensure the API is running and the `API_HOST` and `API_PORT` variables are set correctly.
- **Template errors**: Check that all required template variables are passed to the template.
- **Static file 404 errors**: Ensure file paths in templates use the correct `url_for('static', filename='...')` syntax.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 