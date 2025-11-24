"""Feature extraction for phishing detection."""

import asyncio
import aiohttp
import re
import math
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import tldextract
from loguru import logger

from app.config import settings

class FeatureExtractor:
    """Extract features from URLs and web content for phishing detection."""
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract all features from a URL."""
        try:
            # Extract URL-based features
            url_features = self._extract_url_features(url)
            
            # Extract content-based features
            content_features = await self._extract_content_features(url)
            
            # Extract behavioral features
            behavioral_features = await self._extract_behavioral_features(url)
            
            return {
                "url_features": url_features,
                "content_features": content_features,
                "behavioral_features": behavioral_features
            }
            
        except Exception as e:
            logger.error(f"Feature extraction failed for {url}: {e}")
            return {
                "url_features": {},
                "content_features": {},
                "behavioral_features": {}
            }
    
    def _extract_url_features(self, url: str) -> Dict[str, Any]:
        """Extract features from URL structure."""
        try:
            parsed = urlparse(url)
            domain_info = tldextract.extract(url)
            
            # Basic URL metrics
            url_length = len(url)
            domain_length = len(parsed.netloc)
            path_length = len(parsed.path)
            
            # Character counts
            num_dots = url.count('.')
            num_hyphens = url.count('-')
            num_underscores = url.count('_')
            num_slashes = url.count('/')
            num_questionmarks = url.count('?')
            num_equals = url.count('=')
            num_at = url.count('@')
            num_and = url.count('&')
            num_exclamation = url.count('!')
            num_space = url.count(' ')
            num_tilde = url.count('~')
            num_comma = url.count(',')
            num_plus = url.count('+')
            num_asterisk = url.count('*')
            num_hash = url.count('#')
            num_dollar = url.count('$')
            num_percent = url.count('%')
            
            # Domain analysis
            has_ip = self._is_ip_address(parsed.netloc)
            subdomain_count = len(domain_info.subdomain.split('.')) if domain_info.subdomain else 0
            
            # Suspicious TLD check
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion']
            has_suspicious_tld = any(url.endswith(tld) for tld in suspicious_tlds)
            
            # URL entropy (measure of randomness)
            entropy = self._calculate_entropy(url)
            
            # Path depth
            path_depth = len([p for p in parsed.path.split('/') if p])
            
            # Query parameters
            query_params = parse_qs(parsed.query)
            num_query_params = len(query_params)
            
            # Protocol check
            is_https = parsed.scheme == 'https'
            
            # Suspicious patterns
            has_suspicious_words = any(word in url.lower() for word in [
                'secure', 'account', 'update', 'confirm', 'verify', 'login',
                'signin', 'bank', 'paypal', 'ebay', 'amazon', 'microsoft'
            ])
            
            # Shortening service check
            shortening_services = [
                'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
                'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
            ]
            is_shortened = any(service in parsed.netloc.lower() for service in shortening_services)
            
            return {
                'url_length': url_length,
                'domain_length': domain_length,
                'path_length': path_length,
                'num_dots': num_dots,
                'num_hyphens': num_hyphens,
                'num_underscores': num_underscores,
                'num_slashes': num_slashes,
                'num_questionmarks': num_questionmarks,
                'num_equals': num_equals,
                'num_at': num_at,
                'num_and': num_and,
                'num_exclamation': num_exclamation,
                'num_space': num_space,
                'num_tilde': num_tilde,
                'num_comma': num_comma,
                'num_plus': num_plus,
                'num_asterisk': num_asterisk,
                'num_hash': num_hash,
                'num_dollar': num_dollar,
                'num_percent': num_percent,
                'has_ip': int(has_ip),
                'subdomain_count': subdomain_count,
                'has_suspicious_tld': int(has_suspicious_tld),
                'entropy': entropy,
                'path_depth': path_depth,
                'num_query_params': num_query_params,
                'is_https': int(is_https),
                'has_suspicious_words': int(has_suspicious_words),
                'is_shortened': int(is_shortened)
            }
            
        except Exception as e:
            logger.error(f"URL feature extraction failed: {e}")
            return {}
    
    async def _extract_content_features(self, url: str) -> Dict[str, Any]:
        """Extract features from webpage content."""
        try:
            content = await self._fetch_content(url)
            if not content:
                return {}
            
            soup = BeautifulSoup(content, 'html.parser')
            
            # Basic content metrics
            content_length = len(content)
            text_content = soup.get_text()
            text_length = len(text_content)
            
            # HTML structure analysis
            num_forms = len(soup.find_all('form'))
            num_input_fields = len(soup.find_all('input'))
            num_password_fields = len(soup.find_all('input', {'type': 'password'}))
            num_hidden_fields = len(soup.find_all('input', {'type': 'hidden'}))
            
            # Media content
            num_images = len(soup.find_all('img'))
            num_videos = len(soup.find_all('video'))
            
            # Links analysis
            links = soup.find_all('a', href=True)
            num_links = len(links)
            
            external_links = 0
            internal_links = 0
            for link in links:
                href = link['href']
                if href.startswith('http') and not any(domain in href for domain in [urlparse(url).netloc]):
                    external_links += 1
                else:
                    internal_links += 1
            
            # JavaScript analysis
            scripts = soup.find_all('script')
            num_scripts = len(scripts)
            has_external_scripts = any(script.get('src') for script in scripts if script.get('src'))
            
            # Meta tags
            meta_tags = soup.find_all('meta')
            has_refresh_meta = any(meta.get('http-equiv') == 'refresh' for meta in meta_tags)
            
            # Suspicious content patterns
            suspicious_text_patterns = [
                'verify your account', 'confirm your identity', 'update payment',
                'suspended account', 'click here immediately', 'limited time offer',
                'act now', 'urgent action required'
            ]
            
            has_suspicious_text = any(pattern in text_content.lower() for pattern in suspicious_text_patterns)
            
            # Form analysis
            has_password_field = num_password_fields > 0
            has_credit_card_field = any(
                'credit' in str(input_tag).lower() or 'card' in str(input_tag).lower()
                for input_tag in soup.find_all('input')
            )
            
            return {
                'content_length': content_length,
                'text_length': text_length,
                'num_forms': num_forms,
                'num_input_fields': num_input_fields,
                'num_password_fields': num_password_fields,
                'num_hidden_fields': num_hidden_fields,
                'num_images': num_images,
                'num_videos': num_videos,
                'num_links': num_links,
                'num_external_links': external_links,
                'num_internal_links': internal_links,
                'external_internal_ratio': external_links / max(internal_links, 1),
                'num_scripts': num_scripts,
                'has_external_scripts': int(has_external_scripts),
                'has_refresh_meta': int(has_refresh_meta),
                'has_suspicious_text': int(has_suspicious_text),
                'has_password_field': int(has_password_field),
                'has_credit_card_field': int(has_credit_card_field)
            }
            
        except Exception as e:
            logger.error(f"Content feature extraction failed for {url}: {e}")
            return {}
    
    async def _extract_behavioral_features(self, url: str) -> Dict[str, Any]:
        """Extract behavioral and network-based features."""
        try:
            # Redirect analysis
            redirect_count, final_url = await self._analyze_redirects(url)
            
            # SSL/TLS analysis
            ssl_info = await self._analyze_ssl(url)
            
            # Domain age and reputation (simplified)
            domain_info = self._analyze_domain_reputation(url)
            
            return {
                'redirect_count': redirect_count,
                'url_changed_in_redirect': int(url != final_url),
                'has_ssl': ssl_info.get('has_ssl', 0),
                'ssl_valid': ssl_info.get('ssl_valid', 0),
                'domain_age_days': domain_info.get('age_days', 0),
                'domain_reputation_score': domain_info.get('reputation_score', 0.5)
            }
            
        except Exception as e:
            logger.error(f"Behavioral feature extraction failed for {url}: {e}")
            return {}
    
    async def _fetch_content(self, url: str) -> Optional[str]:
        """Fetch webpage content."""
        try:
            if not self.session:
                timeout = aiohttp.ClientTimeout(total=settings.http_timeout)
                self.session = aiohttp.ClientSession(
                    timeout=timeout,
                    headers={'User-Agent': settings.user_agent}
                )
            
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text()
                return None
                
        except Exception as e:
            logger.warning(f"Failed to fetch content from {url}: {e}")
            return None
    
    async def _analyze_redirects(self, url: str) -> tuple[int, str]:
        """Analyze URL redirects."""
        try:
            if not self.session:
                timeout = aiohttp.ClientTimeout(total=settings.http_timeout)
                self.session = aiohttp.ClientSession(
                    timeout=timeout,
                    headers={'User-Agent': settings.user_agent}
                )
            
            redirect_count = 0
            current_url = url
            
            async with self.session.get(url, allow_redirects=False) as response:
                while response.status in [301, 302, 303, 307, 308] and redirect_count < 10:
                    redirect_count += 1
                    current_url = response.headers.get('Location', current_url)
                    async with self.session.get(current_url, allow_redirects=False) as next_response:
                        response = next_response
            
            return redirect_count, current_url
            
        except Exception as e:
            logger.warning(f"Redirect analysis failed for {url}: {e}")
            return 0, url
    
    async def _analyze_ssl(self, url: str) -> Dict[str, int]:
        """Analyze SSL/TLS configuration."""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return {'has_ssl': 0, 'ssl_valid': 0}
            
            # Simplified SSL check - in production, use more sophisticated validation
            try:
                if not self.session:
                    timeout = aiohttp.ClientTimeout(total=settings.http_timeout)
                    self.session = aiohttp.ClientSession(
                        timeout=timeout,
                        headers={'User-Agent': settings.user_agent}
                    )
                
                async with self.session.get(url) as response:
                    return {'has_ssl': 1, 'ssl_valid': 1 if response.status < 400 else 0}
                    
            except Exception:
                return {'has_ssl': 1, 'ssl_valid': 0}
                
        except Exception:
            return {'has_ssl': 0, 'ssl_valid': 0}
    
    def _analyze_domain_reputation(self, url: str) -> Dict[str, Any]:
        """Analyze domain age and reputation (simplified)."""
        try:
            # In production, integrate with WHOIS and reputation services
            # For now, return mock data based on domain characteristics
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Simple heuristics for demonstration
            suspicious_indicators = [
                len(domain) > 30,
                domain.count('-') > 2,
                any(char.isdigit() for char in domain),
                domain.count('.') > 3
            ]
            
            reputation_score = 1.0 - (sum(suspicious_indicators) * 0.2)
            age_days = 365 if reputation_score > 0.8 else 30  # Mock age based on reputation
            
            return {
                'age_days': age_days,
                'reputation_score': max(0.0, reputation_score)
            }
            
        except Exception:
            return {'age_days': 100, 'reputation_score': 0.5}
    
    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        return bool(ip_pattern.match(hostname))
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        text_length = len(text)
        
        for count in char_counts.values():
            probability = count / text_length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()