"""
Geographic IP Tracker Module
Track and analyze geographic distribution of traffic
"""

import ipaddress


class GeoIPTracker:
    """Track and analyze geographic distribution of traffic"""
    
    def __init__(self):
        self.ip_locations = {}
        self.country_stats = {}
        self.suspicious_countries = ['CN', 'RU', 'KP', 'IR']  # Example list
        
    def lookup_ip(self, ip_address):
        """
        Lookup IP geolocation
        
        Note: This is a simplified implementation.
        For production, use geoip2 library with MaxMind database.
        
        Args:
            ip_address: IP address to lookup
        
        Returns:
            Dictionary with location info
        """
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Check if it's a private IP
            if ip_obj.is_private:
                location = {
                    'ip': ip_address,
                    'country': 'Local',
                    'city': 'Private Network',
                    'lat': 0,
                    'lon': 0,
                    'is_suspicious': False
                }
            else:
                # Mock geolocation data for demonstration
                # In production, use actual GeoIP database
                location = self._mock_geolocation(ip_address)
            
            # Store location
            self.ip_locations[ip_address] = location
            
            # Update country statistics
            country = location['country']
            self.country_stats[country] = self.country_stats.get(country, 0) + 1
            
            return location
            
        except ValueError:
            # Invalid IP address
            return {
                'ip': ip_address,
                'country': 'Invalid',
                'city': 'Unknown',
                'lat': 0,
                'lon': 0,
                'is_suspicious': False
            }
        except Exception as e:
            print(f"[GeoIP] Lookup error: {e}")
            return None
    
    def _mock_geolocation(self, ip_address):
        """
        Generate mock geolocation data
        Replace this with actual GeoIP lookup in production
        """
        # Simple hash-based mock data for demo
        ip_hash = hash(ip_address) % 10
        
        countries = [
            ('US', 'United States', 'New York', 40.7128, -74.0060),
            ('CN', 'China', 'Beijing', 39.9042, 116.4074),
            ('RU', 'Russia', 'Moscow', 55.7558, 37.6173),
            ('DE', 'Germany', 'Berlin', 52.5200, 13.4050),
            ('GB', 'United Kingdom', 'London', 51.5074, -0.1278),
            ('FR', 'France', 'Paris', 48.8566, 2.3522),
            ('IN', 'India', 'Mumbai', 19.0760, 72.8777),
            ('BR', 'Brazil', 'São Paulo', -23.5505, -46.6333),
            ('JP', 'Japan', 'Tokyo', 35.6762, 139.6503),
            ('AU', 'Australia', 'Sydney', -33.8688, 151.2093)
        ]
        
        country_code, country_name, city, lat, lon = countries[ip_hash]
        
        return {
            'ip': ip_address,
            'country': country_name,
            'country_code': country_code,
            'city': city,
            'lat': lat,
            'lon': lon,
            'is_suspicious': country_code in self.suspicious_countries
        }
    
    def get_geographic_report(self):
        """Generate geographic traffic report"""
        report = {
            'total_countries': len(self.country_stats),
            'country_distribution': sorted(
                self.country_stats.items(),
                key=lambda x: x[1],
                reverse=True
            ),
            'suspicious_sources': sum(
                count for country, count in self.country_stats.items()
                if any(susp in country for susp in ['China', 'Russia'])
            ),
            'total_ips_tracked': len(self.ip_locations)
        }
        
        return report
    
    def get_location(self, ip_address):
        """Get stored location for an IP"""
        return self.ip_locations.get(ip_address, None)
    
    def clear_data(self):
        """Clear all geographic data"""
        self.ip_locations.clear()
        self.country_stats.clear()
