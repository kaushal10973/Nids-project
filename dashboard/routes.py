from flask import render_template, jsonify, request, current_app
from nids.database import DatabaseManager
from nids.utils import sanitize_input, validate_ip
import logging

logger = logging.getLogger(__name__)

def create_routes(app, config):
    """Create Flask routes for the dashboard."""
    
    db = DatabaseManager(config['database']['path'])
    
    @app.route('/')
    def index():
        """Main dashboard page."""
        try:
            stats = db.get_statistics()
            recent = db.get_recent_alerts(limit=10)
            
            return render_template('index.html', 
                                 stats=stats, 
                                 recent_alerts=recent,
                                 config=config)
        except Exception as e:
            logger.error(f"Error rendering index: {e}")
            return render_template('error.html', error=str(e)), 500
    
    @app.route('/logs')
    def logs():
        """Historical logs page."""
        try:
            # Get query parameters
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 50))
            
            # Build filters
            filters = {}
            if request.args.get('src_ip'):
                filters['src_ip'] = sanitize_input(request.args.get('src_ip'))
            if request.args.get('dst_ip'):
                filters['dst_ip'] = sanitize_input(request.args.get('dst_ip'))
            if request.args.get('class_label'):
                filters['class_label'] = sanitize_input(request.args.get('class_label'))
            if request.args.get('start_date'):
                filters['start_date'] = request.args.get('start_date')
            if request.args.get('end_date'):
                filters['end_date'] = request.args.get('end_date')
            
            # Query logs
            offset = (page - 1) * per_page
            logs = db.query_logs(filters=filters, limit=per_page, offset=offset)
            
            return render_template('logs.html', 
                                 logs=logs, 
                                 page=page, 
                                 per_page=per_page,
                                 filters=filters)
        except Exception as e:
            logger.error(f"Error rendering logs: {e}")
            return render_template('error.html', error=str(e)), 500
    
    @app.route('/settings')
    def settings():
        """Settings page."""
        return render_template('settings.html', config=config)
    
    # API Endpoints
    
    @app.route('/api/alerts', methods=['GET'])
    def get_alerts():
        """API endpoint to get alerts."""
        try:
            limit = int(request.args.get('limit', 50))
            filters = {}
            
            if request.args.get('since'):
                filters['start_date'] = request.args.get('since')
            
            alerts = db.query_logs(filters=filters, limit=limit)
            return jsonify({'success': True, 'alerts': alerts})
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/alerts', methods=['POST'])
    def add_alert():
        """API endpoint to add alert (for testing)."""
        try:
            data = request.json
            
            # Validate required fields
            required = ['src_ip', 'dst_ip', 'protocol', 'class_label', 'confidence']
            if not all(field in data for field in required):
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400
            
            # Validate IPs
            if not validate_ip(data['src_ip']) or not validate_ip(data['dst_ip']):
                return jsonify({'success': False, 'error': 'Invalid IP address'}), 400
            
            # Store alert
            alert_id = db.store_alert(
                src_ip=data['src_ip'],
                dst_ip=data['dst_ip'],
                protocol=data['protocol'],
                src_port=data.get('src_port', 0),
                dst_port=data.get('dst_port', 0),
                class_label=data['class_label'],
                attack_type=data.get('attack_type'),
                confidence=float(data['confidence']),
                action_taken=data.get('action_taken')
            )
            
            return jsonify({'success': True, 'alert_id': alert_id})
            
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/statistics')
    def get_statistics():
        """API endpoint for statistics."""
        try:
            stats = db.get_statistics()
            return jsonify({'success': True, 'statistics': stats})
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/metrics')
    def get_metrics():
        """API endpoint for traffic metrics/graphs."""
        try:
            # Get alerts from last 24 hours grouped by hour
            from datetime import datetime, timedelta
            
            alerts = db.query_logs(
                filters={'start_date': (datetime.now() - timedelta(hours=24)).isoformat()},
                limit=10000
            )
            
            # Group by hour
            hourly_counts = {}
            for alert in alerts:
                timestamp = datetime.fromisoformat(alert['timestamp'])
                hour_key = timestamp.strftime('%Y-%m-%d %H:00')
                
                if hour_key not in hourly_counts:
                    hourly_counts[hour_key] = {'total': 0, 'attacks': 0}
                
                hourly_counts[hour_key]['total'] += 1
                if alert['class_label'] != 'Normal':
                    hourly_counts[hour_key]['attacks'] += 1
            
            # Convert to list of points
            metrics = {
                'hourly': [
                    {'hour': k, 'total': v['total'], 'attacks': v['attacks']}
                    for k, v in sorted(hourly_counts.items())
                ]
            }
            
            return jsonify({'success': True, 'metrics': metrics})
            
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/health')
    def health():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'service': 'nids',
            'version': '1.0.0'
        })
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return render_template('error.html', error='Page not found'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        logger.error(f"Internal error: {error}")
        return render_template('error.html', error='Internal server error'), 500