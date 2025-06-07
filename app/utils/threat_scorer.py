def score_threat(threat_data):
    score = threat_data.get('num_reports', 0)
    if score >= 10:
        return 'High'
    elif score >= 3:
        return 'Medium'
    else:
        return 'Low'
