def get_threat_info(query):
    # This will be replaced with a real API call!
    # For now, returns mock info
    return {
        'ip': query,
        'num_reports': 3,
        'abuse_types': ['SSH', 'Spam'],
        'country': 'United States',
        'last_reported': '2025-06-01'
    }
