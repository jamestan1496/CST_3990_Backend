#!/usr/bin/env python3
"""
EventHive AI Clustering Microservice
Provides intelligent guest clustering using K-Means and DBSCAN algorithms
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA
import logging
import json
import os
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PORT = int(os.getenv('PORT', 5001))
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'

class AttendeeClusterer:
    """
    Intelligent attendee clustering using machine learning algorithms
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.tfidf_vectorizer = None
        
    def safe_label_encode(self, labels, encoder_name):
        """
        Safely encode labels, handling unknown values gracefully
        """
        try:
            # Always create a fresh encoder for each clustering session
            encoder = LabelEncoder()
            unique_labels = list(set(labels))
            encoder.fit(unique_labels)
            
            # Transform the labels
            encoded = encoder.transform(labels)
            self.label_encoders[encoder_name] = encoder
            
            return encoded
        except Exception as e:
            logger.warning(f"Label encoding failed for {encoder_name}: {e}")
            # Return dummy encoded values
            return np.zeros(len(labels))
        
    def preprocess_data(self, attendee_data):
        """
        Preprocess attendee data for clustering
        """
        try:
            # Convert to DataFrame
            df = pd.DataFrame(attendee_data)
            
            # Feature engineering
            features = []
            feature_names = []
            
            # Process professional roles
            if 'professionalRole' in df.columns:
                if df['professionalRole'].notna().any():
                    roles = df['professionalRole'].fillna('unknown')
                    
                    # Normalize and map roles to standard categories
                    role_mapping = {
                        'software engineer': 'engineer',
                'data scientist': 'data_professional', 
                'ux designer': 'designer',
                'ui designer': 'designer',
                'product manager': 'manager',
                'marketing manager': 'manager',
                'devops engineer': 'engineer',
                'security analyst': 'analyst',
                'financial analyst': 'analyst',
                'ai researcher': 'researcher',
                'startup founder': 'entrepreneur',
                'event manager': 'manager',
                'conference director': 'manager',
                'unknown': 'unknown',
                # Add more comprehensive mappings
                'researcher': 'researcher',
                'engineer': 'engineer',
                'designer': 'designer',
                'manager': 'manager',
                'analyst': 'analyst',
                'entrepreneur': 'entrepreneur',
                'developer': 'engineer',
                'scientist': 'data_professional',
                'director': 'manager',
                'lead': 'manager',
                'senior': 'engineer',  # fallback for "senior X" roles
                'junior': 'engineer'   # fallback for "junior X" roles
                    }
                    
                    # Normalize and map roles
                    normalized_roles = []
                    for role in roles:
                        normalized_role = role.lower().strip() if role else 'unknown'
                        mapped_role = role_mapping.get(normalized_role, 'other')
                        normalized_roles.append(mapped_role)
                    
                    # Use safe encoding
                    role_encoded = self.safe_label_encode(normalized_roles, 'professionalRole')
                    features.append(role_encoded.reshape(-1, 1))
                    feature_names.append('professional_role')
            
            # Process interests using TF-IDF
            if 'interests' in df.columns:
                interests_text = df['interests'].apply(
                    lambda x: ' '.join(x) if isinstance(x, list) and x else 'general'
                )
                
                if interests_text.notna().any():
                    try:
                        # Create a fresh vectorizer for each clustering session
                        self.tfidf_vectorizer = TfidfVectorizer(
                            max_features=50, 
                            stop_words='english',
                            lowercase=True,
                            token_pattern=r'\b[a-zA-Z][a-zA-Z-]*\b'
                        )
                        interests_tfidf = self.tfidf_vectorizer.fit_transform(interests_text)
                        features.append(interests_tfidf.toarray())
                        feature_names.extend([f'interest_{i}' for i in range(interests_tfidf.shape[1])])
                    except Exception as e:
                        logger.warning(f"Could not process interests with TF-IDF: {e}")
                        # Fallback: count number of interests
                        interest_counts = df['interests'].apply(
                            lambda x: len(x) if isinstance(x, list) else 0
                        )
                        features.append(interest_counts.values.reshape(-1, 1))
                        feature_names.append('interest_count')
            
            # If no features were extracted, create dummy features
            if not features:
                logger.warning("No features extracted, using dummy features")
                dummy_features = np.random.rand(len(df), 2)
                features.append(dummy_features)
                feature_names.extend(['dummy_1', 'dummy_2'])
            
            # Combine all features
            if len(features) == 1:
                feature_matrix = features[0]
            else:
                feature_matrix = np.hstack(features)
            
            # Handle any remaining NaN values
            feature_matrix = np.nan_to_num(feature_matrix)
            
            # Scale features
            feature_matrix_scaled = self.scaler.fit_transform(feature_matrix)
            
            return feature_matrix_scaled, feature_names, df
            
        except Exception as e:
            logger.error(f"Error in preprocessing: {e}")
            raise
    
    def kmeans_clustering(self, features, n_clusters=3):
        """
        Perform K-Means clustering
        """
        try:
            # Determine optimal number of clusters if not specified
            if n_clusters == 'auto':
                n_clusters = min(8, max(2, len(features) // 3))
            
            # Ensure we don't have more clusters than data points
            n_clusters = min(n_clusters, len(features))
            
            kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
            cluster_labels = kmeans.fit_predict(features)
            
            # Calculate metrics
            if len(set(cluster_labels)) > 1:
                silhouette_avg = silhouette_score(features, cluster_labels)
            else:
                silhouette_avg = 0
            
            return cluster_labels, {
                'algorithm': 'K-Means',
                'n_clusters': n_clusters,
                'silhouette_score': float(silhouette_avg),
                'inertia': float(kmeans.inertia_)
            }
            
        except Exception as e:
            logger.error(f"Error in K-Means clustering: {e}")
            raise
    
    def dbscan_clustering(self, features, eps=0.5, min_samples=2):
        """
        Perform DBSCAN clustering
        """
        try:
            dbscan = DBSCAN(eps=eps, min_samples=min_samples)
            cluster_labels = dbscan.fit_predict(features)
            
            # Calculate metrics
            n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels else 0)
            n_noise = list(cluster_labels).count(-1)
            
            if n_clusters > 1:
                # Only calculate silhouette score if we have more than one cluster
                non_noise_mask = cluster_labels != -1
                if np.sum(non_noise_mask) > 1:
                    silhouette_avg = silhouette_score(
                        features[non_noise_mask], 
                        cluster_labels[non_noise_mask]
                    )
                else:
                    silhouette_avg = 0
            else:
                silhouette_avg = 0
            
            return cluster_labels, {
                'algorithm': 'DBSCAN',
                'n_clusters': n_clusters,
                'n_noise_points': n_noise,
                'silhouette_score': float(silhouette_avg),
                'eps': eps,
                'min_samples': min_samples
            }
            
        except Exception as e:
            logger.error(f"Error in DBSCAN clustering: {e}")
            raise
    
    def cluster_attendees(self, attendee_data, algorithm='kmeans', **kwargs):
        """
        Main clustering function
        """
        try:
            if len(attendee_data) < 2:
                raise ValueError("Need at least 2 attendees for clustering")
                
            # Preprocess data
            features, feature_names, df = self.preprocess_data(attendee_data)
            
            if features.shape[0] < 2:
                raise ValueError("Insufficient data for clustering")
            
            # Perform clustering
            if algorithm.lower() == 'kmeans':
                n_clusters = kwargs.get('numClusters', 3)
                # Ensure we don't have more clusters than data points
                n_clusters = min(n_clusters, len(attendee_data))
                cluster_labels, metrics = self.kmeans_clustering(features, n_clusters)
            elif algorithm.lower() == 'dbscan':
                eps = kwargs.get('eps', 0.5)
                min_samples = kwargs.get('minSamples', 2)
                cluster_labels, metrics = self.dbscan_clustering(features, eps, min_samples)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Organize results
            clusters = {}
            for i, label in enumerate(cluster_labels):
                cluster_name = f"cluster_{label}" if label != -1 else "noise"
                if cluster_name not in clusters:
                    clusters[cluster_name] = []
                clusters[cluster_name].append(attendee_data[i]['id'])
            
            # Convert to list format expected by the backend
            cluster_list = []
            cluster_info = []
            
            for cluster_name, member_ids in clusters.items():
                if cluster_name != "noise":  # Skip noise cluster for now
                    cluster_list.append(member_ids)
                    
                    # Get cluster statistics
                    cluster_members = [attendee_data[i] for i in range(len(attendee_data)) 
                                     if attendee_data[i]['id'] in member_ids]
                    
                    # Analyze cluster characteristics
                    roles = [m.get('professionalRole', 'unknown') for m in cluster_members]
                    interests = []
                    for m in cluster_members:
                        if isinstance(m.get('interests'), list):
                            interests.extend(m['interests'])
                    
                    most_common_role = max(set(roles), key=roles.count) if roles else 'unknown'
                    most_common_interests = list(set(interests))[:3] if interests else []
                    
                    cluster_info.append({
                        'id': cluster_name,
                        'size': len(member_ids),
                        'dominant_role': most_common_role,
                        'common_interests': most_common_interests,
                        'members': cluster_members
                    })
            
            # Enhanced metrics
            metrics.update({
                'total_attendees': len(attendee_data),
                'features_used': feature_names,
                'cluster_distribution': [len(cluster) for cluster in cluster_list],
                'timestamp': datetime.now().isoformat()
            })
            
            return cluster_list, cluster_info, metrics
            
        except Exception as e:
            logger.error(f"Error in clustering: {e}")
            # Return a simple fallback clustering based on professional roles
            return self.fallback_clustering(attendee_data)

# Initialize clusterer
clusterer = AttendeeClusterer()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'EventHive Clustering Service',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/cluster', methods=['POST'])
def cluster_attendees():
    """
    Cluster attendees based on their profiles
    """
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        attendee_data = data.get('data', [])
        algorithm = data.get('algorithm', 'kmeans').lower()
        
        if not attendee_data:
            return jsonify({'error': 'No attendee data provided'}), 400
        
        # Validate attendee data structure
        for i, attendee in enumerate(attendee_data):
            if 'id' not in attendee:
                return jsonify({'error': f'Missing id for attendee at index {i}'}), 400
        
        # Get algorithm-specific parameters
        clustering_params = {}
        if algorithm == 'kmeans':
            clustering_params['numClusters'] = data.get('numClusters', 3)
        elif algorithm == 'dbscan':
            clustering_params['eps'] = data.get('eps', 0.5)
            clustering_params['minSamples'] = data.get('minSamples', 2)
        
        # Perform clustering
        clusters, cluster_info, metrics = clusterer.cluster_attendees(
            attendee_data, 
            algorithm, 
            **clustering_params
        )
        
        logger.info(f"Clustering completed: {len(clusters)} clusters for {len(attendee_data)} attendees")
        
        return jsonify({
            'clusters': clusters,
            'cluster_info': cluster_info,
            'metrics': metrics,
            'success': True
        })
        
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Clustering error: {e}")
        return jsonify({'error': 'Clustering failed', 'details': str(e)}), 500

@app.route('/cluster/analyze', methods=['POST'])
def analyze_clusters():
    """
    Analyze existing clusters and provide insights
    """
    try:
        data = request.get_json()
        clusters = data.get('clusters', [])
        attendee_data = data.get('attendeeData', [])
        
        if not clusters or not attendee_data:
            return jsonify({'error': 'Clusters and attendee data required'}), 400
        
        # Create attendee lookup
        attendee_lookup = {att['id']: att for att in attendee_data}
        
        analysis = []
        for i, cluster in enumerate(clusters):
            cluster_members = [attendee_lookup[att_id] for att_id in cluster if att_id in attendee_lookup]
            
            if not cluster_members:
                continue
            
            # Analyze cluster characteristics
            roles = [m.get('professionalRole', 'unknown') for m in cluster_members]
            interests = []
            for m in cluster_members:
                if isinstance(m.get('interests'), list):
                    interests.extend(m['interests'])
            
            role_counts = {}
            for role in roles:
                role_counts[role] = role_counts.get(role, 0) + 1
            
            interest_counts = {}
            for interest in interests:
                interest_counts[interest] = interest_counts.get(interest, 0) + 1
            
            # Get top characteristics
            top_roles = sorted(role_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_interests = sorted(interest_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            cluster_analysis = {
                'cluster_id': i,
                'size': len(cluster_members),
                'top_roles': top_roles,
                'top_interests': top_interests,
                'diversity_score': len(set(roles)) / len(roles) if roles else 0,
                'avg_interests_per_person': len(interests) / len(cluster_members) if cluster_members else 0,
                'suggested_activities': _suggest_activities(top_interests, top_roles),
                'networking_potential': _calculate_networking_potential(cluster_members)
            }
            
            analysis.append(cluster_analysis)
        
        return jsonify({
            'analysis': analysis,
            'summary': {
                'total_clusters': len(analysis),
                'total_attendees': len(attendee_data),
                'avg_cluster_size': sum(a['size'] for a in analysis) / len(analysis) if analysis else 0
            }
        })
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': 'Analysis failed', 'details': str(e)}), 500

def _suggest_activities(top_interests, top_roles):
    """Suggest activities based on cluster characteristics"""
    suggestions = []
    
    # Interest-based suggestions
    for interest, count in top_interests[:3]:
        if 'technology' in interest.lower():
            suggestions.append('Tech Demo Session')
        elif 'business' in interest.lower():
            suggestions.append('Business Networking Lunch')
        elif 'design' in interest.lower():
            suggestions.append('Design Workshop')
        elif 'marketing' in interest.lower():
            suggestions.append('Marketing Strategy Panel')
    
    # Role-based suggestions
    for role, count in top_roles[:2]:
        if 'engineer' in role.lower():
            suggestions.append('Technical Deep Dive')
        elif 'manager' in role.lower():
            suggestions.append('Leadership Discussion')
        elif 'designer' in role.lower():
            suggestions.append('Creative Collaboration')
    
    return list(set(suggestions))[:5]  # Remove duplicates and limit

def _calculate_networking_potential(cluster_members):
    """Calculate networking potential score"""
    if len(cluster_members) < 2:
        return 0
    
    # Based on diversity of roles and interests
    roles = set(m.get('professionalRole', 'unknown') for m in cluster_members)
    all_interests = set()
    for m in cluster_members:
        if isinstance(m.get('interests'), list):
            all_interests.update(m['interests'])
    
    # Higher score for more diversity
    role_diversity = len(roles) / len(cluster_members)
    interest_diversity = len(all_interests) / len(cluster_members)
    
    # Optimal cluster size factor (peak around 6-8 people)
    size_factor = min(1.0, len(cluster_members) / 8)
    
    return (role_diversity + interest_diversity + size_factor) / 3

@app.route('/algorithms', methods=['GET'])
def get_available_algorithms():
    """Get list of available clustering algorithms"""
    return jsonify({
        'algorithms': [
            {
                'name': 'kmeans',
                'display_name': 'K-Means',
                'description': 'Partitions data into k clusters',
                'parameters': [
                    {'name': 'numClusters', 'type': 'integer', 'default': 3, 'min': 2, 'max': 10}
                ]
            },
            {
                'name': 'dbscan',
                'display_name': 'DBSCAN',
                'description': 'Density-based clustering that can find clusters of arbitrary shape',
                'parameters': [
                    {'name': 'eps', 'type': 'float', 'default': 0.5, 'min': 0.1, 'max': 2.0},
                    {'name': 'minSamples', 'type': 'integer', 'default': 2, 'min': 1, 'max': 10}
                ]
            }
        ]
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info(f"Starting EventHive Clustering Service on port {PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=DEBUG)