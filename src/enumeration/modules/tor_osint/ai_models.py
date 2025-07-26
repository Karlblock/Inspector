"""
AI Defensive Tor - Machine learning models for threat detection and classification
"""

import numpy as np
import pickle
import joblib
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

from ....utils.logger import Logger


class PhishingMLModel:
    """ML model for detecting phishing sites"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        
        # Phishing indicators
        self.phishing_keywords = [
            'verify', 'suspended', 'confirm', 'update', 'limited time',
            'click here', 'act now', 'urgent', 'expire', 'secure your'
        ]
        
        self.legitimate_keywords = [
            'privacy', 'terms', 'about', 'contact', 'help',
            'documentation', 'support', 'official', 'verified'
        ]
    
    def extract_features(self, content: str, url: str = '') -> Dict:
        """Extract features from content and URL"""
        features = {
            'url_length': len(url),
            'has_ip': bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
            'subdomain_count': url.count('.') - 1,
            'has_https': url.startswith('https'),
            'suspicious_tld': any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf']),
            
            # Content features
            'form_count': content.lower().count('<form'),
            'input_count': content.lower().count('<input'),
            'password_field_count': content.lower().count('type="password"') + content.lower().count("type='password'"),
            'external_links': len(re.findall(r'https?://[^\s<>"]+', content)),
            'mailto_links': content.lower().count('mailto:'),
            
            # Keyword features
            'phishing_keyword_count': sum(1 for kw in self.phishing_keywords if kw in content.lower()),
            'legitimate_keyword_count': sum(1 for kw in self.legitimate_keywords if kw in content.lower()),
            
            # JavaScript features
            'has_popup': 'window.open' in content or 'popup' in content.lower(),
            'has_redirect': 'window.location' in content or 'redirect' in content.lower(),
            'obfuscated_js': bool(re.search(r'eval\(|unescape\(|fromCharCode\(', content))
        }
        
        # Text complexity
        words = word_tokenize(content.lower())
        features['word_count'] = len(words)
        features['unique_word_ratio'] = len(set(words)) / len(words) if words else 0
        
        return features
    
    def predict_phishing_probability(self, content: str, url: str = '') -> Tuple[float, Dict]:
        """Predict probability of phishing"""
        features = self.extract_features(content, url)
        
        # Rule-based scoring for immediate use (before ML model is trained)
        score = 0.0
        reasons = []
        
        # URL-based scoring
        if features['has_ip']:
            score += 0.2
            reasons.append('IP address in URL')
        
        if features['suspicious_tld']:
            score += 0.15
            reasons.append('Suspicious TLD')
        
        if not features['has_https']:
            score += 0.1
            reasons.append('No HTTPS')
        
        # Content-based scoring
        if features['password_field_count'] > 0:
            score += 0.2
            reasons.append(f"{features['password_field_count']} password fields")
        
        if features['phishing_keyword_count'] > 3:
            score += 0.25
            reasons.append(f"{features['phishing_keyword_count']} phishing keywords")
        
        if features['obfuscated_js']:
            score += 0.2
            reasons.append('Obfuscated JavaScript')
        
        # Legitimate indicators (reduce score)
        if features['legitimate_keyword_count'] > 5:
            score -= 0.1
            reasons.append(f"{features['legitimate_keyword_count']} legitimate keywords (good)")
        
        # Normalize score
        score = max(0.0, min(1.0, score))
        
        return score, {
            'probability': score,
            'features': features,
            'reasons': reasons,
            'classification': 'phishing' if score > 0.5 else 'legitimate'
        }


class ContentClassifier:
    """Classify content into categories"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        
        # Content categories and their indicators
        self.categories = {
            'marketplace': {
                'keywords': ['buy', 'sell', 'price', 'cart', 'checkout', 'payment', 'bitcoin', 'btc'],
                'patterns': [r'add.?to.?cart', r'\$\d+', r'฿\s*\d+'],
                'weight': 1.0
            },
            'forum': {
                'keywords': ['post', 'reply', 'thread', 'topic', 'member', 'register', 'login'],
                'patterns': [r'posted\s+by', r'last\s+post', r'\d+\s+replies'],
                'weight': 0.8
            },
            'blog': {
                'keywords': ['article', 'blog', 'post', 'author', 'published', 'comments'],
                'patterns': [r'published\s+on', r'by\s+\w+\s+on', r'read\s+more'],
                'weight': 0.7
            },
            'phishing': {
                'keywords': ['verify', 'suspended', 'confirm', 'urgent', 'expire'],
                'patterns': [r'verify\s+your\s+account', r'suspended\s+account'],
                'weight': 1.2
            },
            'malware': {
                'keywords': ['download', 'install', 'update', 'exe', 'virus', 'trojan'],
                'patterns': [r'download\s+now', r'\.exe', r'flash\s+player'],
                'weight': 1.3
            },
            'legitimate': {
                'keywords': ['privacy', 'terms', 'about', 'contact', 'official'],
                'patterns': [r'terms\s+of\s+service', r'privacy\s+policy'],
                'weight': 0.5
            }
        }
    
    def classify_content(self, content: str, url: str = '') -> Dict:
        """Classify content into categories"""
        content_lower = content.lower()
        scores = {}
        
        for category, indicators in self.categories.items():
            score = 0.0
            matched_indicators = []
            
            # Check keywords
            for keyword in indicators['keywords']:
                if keyword in content_lower:
                    score += 0.1
                    matched_indicators.append(f"keyword:{keyword}")
            
            # Check patterns
            for pattern in indicators['patterns']:
                matches = re.findall(pattern, content_lower)
                if matches:
                    score += 0.15 * len(matches)
                    matched_indicators.append(f"pattern:{pattern}")
            
            # Apply category weight
            score *= indicators['weight']
            
            scores[category] = {
                'score': min(score, 1.0),
                'indicators': matched_indicators
            }
        
        # Determine primary category
        primary_category = max(scores, key=lambda k: scores[k]['score'])
        confidence = scores[primary_category]['score']
        
        return {
            'primary_category': primary_category,
            'confidence': confidence,
            'all_scores': scores,
            'is_malicious': primary_category in ['phishing', 'malware', 'marketplace']
        }


class ThreatPredictor:
    """Predict future threats based on patterns"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.threat_patterns = []
        self.neural_net = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            random_state=42
        )
    
    def analyze_threat_evolution(self, historical_data: List[Dict]) -> Dict:
        """Analyze how threats evolve over time"""
        if not historical_data:
            return {'error': 'No historical data provided'}
        
        evolution = {
            'threat_progression': [],
            'predicted_next_steps': [],
            'risk_trajectory': 'stable'
        }
        
        # Analyze progression
        if len(historical_data) >= 2:
            # Simple trend analysis
            risk_scores = [d.get('risk_score', 0) for d in historical_data]
            
            if risk_scores[-1] > risk_scores[0]:
                evolution['risk_trajectory'] = 'increasing'
            elif risk_scores[-1] < risk_scores[0]:
                evolution['risk_trajectory'] = 'decreasing'
            
            # Predict next steps based on patterns
            last_threats = historical_data[-1].get('threats', [])
            
            threat_progressions = {
                'phishing': ['credential_harvesting', 'account_takeover', 'data_exfiltration'],
                'malware': ['initial_infection', 'persistence', 'command_control', 'data_theft'],
                'scam': ['initial_contact', 'trust_building', 'payment_request', 'disappear']
            }
            
            for threat_type, progression in threat_progressions.items():
                if threat_type in str(last_threats):
                    # Find current stage and predict next
                    for i, stage in enumerate(progression[:-1]):
                        if stage in str(historical_data):
                            evolution['predicted_next_steps'].append({
                                'threat': threat_type,
                                'next_stage': progression[i + 1],
                                'probability': 0.7 - (i * 0.1)
                            })
        
        return evolution
    
    def predict_threat_likelihood(self, indicators: Dict) -> Dict:
        """Predict likelihood of different threat scenarios"""
        predictions = {
            'targeted_attack': 0.0,
            'opportunistic_attack': 0.0,
            'data_breach': 0.0,
            'brand_damage': 0.0,
            'financial_loss': 0.0
        }
        
        # Simple rule-based prediction (in production, this would use trained ML model)
        
        # Targeted attack indicators
        if indicators.get('organization_specific_content'):
            predictions['targeted_attack'] += 0.4
        if indicators.get('sophisticated_techniques'):
            predictions['targeted_attack'] += 0.3
        
        # Opportunistic attack indicators
        if indicators.get('generic_phishing'):
            predictions['opportunistic_attack'] += 0.5
        if indicators.get('mass_scanning'):
            predictions['opportunistic_attack'] += 0.3
        
        # Data breach indicators
        if indicators.get('data_exfiltration_capability'):
            predictions['data_breach'] += 0.6
        if indicators.get('database_keywords'):
            predictions['data_breach'] += 0.2
        
        # Brand damage indicators
        if indicators.get('impersonation'):
            predictions['brand_damage'] += 0.7
        if indicators.get('negative_association'):
            predictions['brand_damage'] += 0.3
        
        # Financial loss indicators
        if indicators.get('payment_processing'):
            predictions['financial_loss'] += 0.6
        if indicators.get('crypto_addresses'):
            predictions['financial_loss'] += 0.4
        
        # Normalize scores
        for threat in predictions:
            predictions[threat] = min(predictions[threat], 1.0)
        
        # Determine highest risk
        highest_risk = max(predictions, key=predictions.get)
        
        return {
            'predictions': predictions,
            'highest_risk': highest_risk,
            'risk_level': predictions[highest_risk],
            'recommended_actions': self._get_recommended_actions(highest_risk)
        }
    
    def _get_recommended_actions(self, threat_type: str) -> List[str]:
        """Get recommended actions for threat type"""
        recommendations = {
            'targeted_attack': [
                'Implement enhanced monitoring',
                'Review and update security controls',
                'Conduct threat hunting exercises',
                'Brief security team on specific threat'
            ],
            'opportunistic_attack': [
                'Ensure patches are up to date',
                'Review access controls',
                'Enhance user awareness training',
                'Monitor for automated scanning'
            ],
            'data_breach': [
                'Review data access logs',
                'Implement data loss prevention',
                'Encrypt sensitive data',
                'Prepare incident response team'
            ],
            'brand_damage': [
                'Monitor for brand mentions',
                'Prepare takedown requests',
                'Alert legal team',
                'Prepare public communications'
            ],
            'financial_loss': [
                'Review financial controls',
                'Monitor transactions',
                'Alert finance team',
                'Prepare fraud response procedures'
            ]
        }
        
        return recommendations.get(threat_type, ['Continue monitoring'])


class AIDefensiveTor:
    """Main AI defensive system coordinator"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.phishing_model = PhishingMLModel()
        self.content_classifier = ContentClassifier()
        self.threat_predictor = ThreatPredictor()
    
    def analyze_with_ai(self, content: str, url: str, 
                       metadata: Dict = None) -> Dict:
        """Perform comprehensive AI analysis"""
        self.logger.info(f"Starting AI analysis for {url}")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'ai_classification': {},
            'threat_prediction': {},
            'confidence_scores': {},
            'recommendations': []
        }
        
        try:
            # Phishing detection
            phishing_prob, phishing_details = self.phishing_model.predict_phishing_probability(
                content, url
            )
            analysis['ai_classification']['phishing'] = phishing_details
            
            # Content classification
            content_class = self.content_classifier.classify_content(content, url)
            analysis['ai_classification']['content'] = content_class
            
            # Threat prediction
            indicators = self._extract_threat_indicators(content, url, metadata)
            threat_pred = self.threat_predictor.predict_threat_likelihood(indicators)
            analysis['threat_prediction'] = threat_pred
            
            # Overall confidence
            analysis['confidence_scores'] = {
                'phishing_detection': phishing_prob,
                'content_classification': content_class['confidence'],
                'threat_prediction': threat_pred['risk_level']
            }
            
            # Generate recommendations
            analysis['recommendations'] = self._generate_ai_recommendations(analysis)
            
        except Exception as e:
            self.logger.error(f"AI analysis error: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _extract_threat_indicators(self, content: str, url: str, 
                                 metadata: Dict = None) -> Dict:
        """Extract indicators for threat prediction"""
        indicators = {
            'organization_specific_content': False,
            'sophisticated_techniques': False,
            'generic_phishing': False,
            'mass_scanning': False,
            'data_exfiltration_capability': False,
            'database_keywords': False,
            'impersonation': False,
            'negative_association': False,
            'payment_processing': False,
            'crypto_addresses': False
        }
        
        content_lower = content.lower()
        
        # Check for various indicators
        if metadata and metadata.get('organization_name'):
            if metadata['organization_name'].lower() in content_lower:
                indicators['organization_specific_content'] = True
        
        # Sophisticated techniques
        if any(tech in content_lower for tech in ['0day', 'zero-day', 'exploit', 'cve-']):
            indicators['sophisticated_techniques'] = True
        
        # Generic phishing
        if any(phrase in content_lower for phrase in ['dear customer', 'valued user', 'click here']):
            indicators['generic_phishing'] = True
        
        # Database keywords
        if any(db in content_lower for db in ['database', 'mysql', 'mongodb', 'postgres']):
            indicators['database_keywords'] = True
        
        # Payment processing
        if any(payment in content_lower for payment in ['payment', 'credit card', 'paypal', 'stripe']):
            indicators['payment_processing'] = True
        
        # Crypto addresses
        btc_pattern = r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
        if re.search(btc_pattern, content):
            indicators['crypto_addresses'] = True
        
        return indicators
    
    def _generate_ai_recommendations(self, analysis: Dict) -> List[str]:
        """Generate AI-based recommendations"""
        recommendations = []
        
        # Based on phishing score
        phishing_score = analysis['confidence_scores']['phishing_detection']
        if phishing_score > 0.7:
            recommendations.append('CRITICAL: High probability of phishing. Block immediately.')
        elif phishing_score > 0.4:
            recommendations.append('WARNING: Potential phishing site. Monitor closely.')
        
        # Based on content classification
        content_type = analysis['ai_classification']['content']['primary_category']
        if content_type in ['malware', 'phishing']:
            recommendations.append(f'Detected as {content_type}. Initiate incident response.')
        
        # Based on threat prediction
        highest_threat = analysis['threat_prediction']['highest_risk']
        if analysis['threat_prediction']['risk_level'] > 0.6:
            recommendations.append(f'High risk of {highest_threat}. Take preventive action.')
        
        # Add specific actions from threat predictor
        recommendations.extend(
            analysis['threat_prediction']['recommended_actions']
        )
        
        return recommendations
    
    def train_models(self, training_data: List[Dict]) -> Dict:
        """Train ML models with labeled data"""
        # This would be implemented with actual training logic
        # For now, returning training status
        return {
            'status': 'not_implemented',
            'message': 'Model training requires labeled dataset'
        }
    
    def get_model_performance(self) -> Dict:
        """Get performance metrics of AI models"""
        return {
            'phishing_model': {
                'accuracy': 'N/A',
                'precision': 'N/A',
                'recall': 'N/A',
                'last_trained': 'Never'
            },
            'content_classifier': {
                'accuracy': 'N/A',
                'categories': list(self.content_classifier.categories.keys())
            },
            'threat_predictor': {
                'prediction_types': list(self.threat_predictor.predict_threat_likelihood({})['predictions'].keys())
            }
        }