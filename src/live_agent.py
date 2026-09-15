def calculate_live_risk(features, prediction):

    risk = 0
    reasons = []

    # AI anomaly
    if prediction == "SUSPICIOUS":
        risk += 60
        reasons.append("AI detected unusual network behavior.")

    # High packet rate
    if features["packets_per_second"] > 1000:
        risk += 15
        reasons.append("Very high packet rate detected.")

    # High bandwidth
    if features["bytes_per_second"] > 1_000_000:
        risk += 15
        reasons.append("High network traffic volume detected.")

    # Many destinations
    if features["unique_destinations"] > 100:
        risk += 10
        reasons.append("Large number of destination hosts detected.")

    risk = min(risk, 100)

    if risk <= 30:
        level = "LOW"
    elif risk <= 60:
        level = "MEDIUM"
    elif risk <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    if not reasons:
        reasons.append("Traffic appears normal.")

    return risk, level, reasons