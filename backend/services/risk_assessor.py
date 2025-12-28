"""
VulneraAI - Risk Assessment Service
"""

class RiskAssessor:
    def __init__(self, scan):
        self.scan = scan
        self.severity_scores = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3
        }

    def assess(self):
        """Calculate risk score and assessment"""
        score = self._calculate_risk_score()
        level = self._get_risk_level(score)
        reasoning = self._generate_reasoning(score, level)
        recommendations = self._generate_recommendations()
        affected_services = self._get_affected_services()

        self.scan.risk_score = score
        self.scan.risk_level = level
        self.scan.save()

        return {
            'scanId': self.scan.id,
            'score': score,
            'level': level,
            'reasoning': reasoning,
            'recommendations': recommendations,
            'affectedServices': affected_services
        }

    def _calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        if not self.scan.vulnerabilities:
            return 0

        total_score = 0
        for vuln in self.scan.vulnerabilities:
            total_score += self.severity_scores.get(vuln.severity, 0)

        # Normalize to 0-100 scale
        max_score = 100  # Maximum possible score
        score = min(int((total_score / max_score) * 100), 100)

        return score

    def _get_risk_level(self, score):
        """Determine risk level from score"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'

    def _generate_reasoning(self, score, level):
        """Generate AI-powered reasoning"""
        if not self.scan.vulnerabilities:
            return 'No significant vulnerabilities detected. Continue monitoring.'

        # Count vulnerabilities by severity
        severity_counts = {
            'critical': sum(1 for v in self.scan.vulnerabilities if v.severity == 'critical'),
            'high': sum(1 for v in self.scan.vulnerabilities if v.severity == 'high'),
            'medium': sum(1 for v in self.scan.vulnerabilities if v.severity == 'medium'),
            'low': sum(1 for v in self.scan.vulnerabilities if v.severity == 'low')
        }

        reasoning_templates = {
            'CRITICAL': f"Immediate action required. The system has {severity_counts['critical']} critical and {severity_counts['high']} high-severity vulnerabilities that pose severe security risks.",
            'HIGH': f"Urgent remediation needed. {severity_counts['high']} high-risk vulnerabilities should be addressed quickly.",
            'MEDIUM': f"Plan remediation. {severity_counts['medium']} medium-risk issues should be addressed in the near term.",
            'LOW': f"Monitor and document. {severity_counts['low']} low-risk issues may be addressed in regular maintenance.",
            'MINIMAL': 'No significant vulnerabilities detected. Continue monitoring.'
        }

        return reasoning_templates.get(level, 'Unable to assess risk.')

    def _generate_recommendations(self):
        """Generate remediation recommendations"""
        recommendations = []
        affected_services = set()

        for vuln in self.scan.vulnerabilities:
            affected_services.add(vuln.service)

        # Disable critical services
        critical_services = {'Telnet', 'FTP'}
        for service in critical_services:
            if service in affected_services:
                recommendations.append(f'Disable {service} service immediately')

        # Update TLS
        if 'HTTPS' in affected_services:
            recommendations.append('Update TLS configuration to version 1.2 or higher')

        # Firewall rules
        if len(self.scan.vulnerabilities) > 2:
            recommendations.append('Implement strict firewall rules to limit port exposure')

        # Intrusion detection
        if any(v.severity == 'critical' for v in self.scan.vulnerabilities):
            recommendations.append('Enable intrusion detection and prevention systems')

        # Regular updates
        recommendations.append('Keep all systems and software updated with latest patches')

        # Monitoring
        recommendations.append('Implement continuous vulnerability scanning and monitoring')

        return recommendations[:5]  # Return top 5

    def _get_affected_services(self):
        """Get list of affected services"""
        return list(set(v.service for v in self.scan.vulnerabilities))
