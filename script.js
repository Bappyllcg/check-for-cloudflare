$(document).ready(function() {
    // Handle form submission
    $('#scan-button').on('click', function() {
        checkForCloudflare();
    });

    // Also trigger check when Enter key is pressed in the input field
    $('#url-input').on('keypress', function(e) {
        if (e.which === 13) { // Enter key
            checkForCloudflare();
        }
    });

    function checkForCloudflare() {
        const url = $('#url-input').val().trim();
        
        // Basic URL validation
        if (!url) {
            showError('Please enter a valid URL');
            return;
        }

        // Format URL if needed
        let formattedUrl = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            formattedUrl = 'https://' + url;
        }

        // Show loading state
        showLoading();

        // Use a proxy to avoid CORS issues
        const proxyUrl = 'https://api.allorigins.win/get?url=' + encodeURIComponent(formattedUrl);

        // Make the request
        $.ajax({
            url: proxyUrl,
            type: 'GET',
            dataType: 'json',
            success: function(response) {
                processResponse(formattedUrl, response);
            },
            error: function(xhr, status, error) {
                showError('Error checking the website: ' + error);
            }
        });
    }

    function processResponse(originalUrl, response) {
        // Initialize results
        let results = {
            url: originalUrl,
            isCloudflare: false,
            evidence: [],
            cdnOrProxy: null,
            cdnEvidence: [],
            nameservers: [],
            nsEvidence: []
        };
    
        try {
            // Check if we got a valid response
            if (response && (response.contents || response.headers)) {
                const headers = parseHeaders(response);
    
                // Updated detection logic
                const cloudflareIndicators = [
                    { key: 'cf-ray', message: 'CF-Ray header found' },
                    { key: 'cf-cache-status', message: 'CF-Cache-Status header found' },
                    { key: 'server', message: 'Server header indicates Cloudflare', test: val => val.toLowerCase().includes('cloudflare') },
                    { key: 'cloudflare-cookie', message: 'Cloudflare cookie detected' },
                    { key: 'cloudflare-scripts', message: 'Cloudflare scripts detected' },
                    { key: 'cloudflare-captcha', message: 'Cloudflare security challenge detected' },
                    { key: 'cloudflare-honeypot', message: 'Cloudflare security honeypot detected' },
                    { key: 'cf-ssl', message: 'Cloudflare SSL detected' }
                ];
    
                cloudflareIndicators.forEach(indicator => {
                    const value = headers[indicator.key];
                    if (value && (!indicator.test || indicator.test(value))) {
                        results.isCloudflare = true;
                        results.evidence.push(`${indicator.message}: ${value}`);
                    }
                });
    
                // Fallback check for any Cloudflare mention in HTML
                if (response.contents && response.contents.toLowerCase().includes('cloudflare')) {
                    results.isCloudflare = true;
                    results.evidence.push('Cloudflare mentioned in page content');
                }
    
                // CDN/Proxy detection logic
                const cdnProxyIndicators = [
                    { key: 'server', name: 'Akamai', test: v => v.toLowerCase().includes('akamai') },
                    { key: 'x-akamai-transformed', name: 'Akamai' },
                    { key: 'x-cache', name: 'Akamai', test: v => v.toLowerCase().includes('akamai') },
                    { key: 'x-cdn', name: 'Fastly', test: v => v.toLowerCase().includes('fastly') },
                    { key: 'x-served-by', name: 'Fastly', test: v => v.toLowerCase().includes('fastly') },
                    { key: 'x-cache', name: 'Fastly', test: v => v.toLowerCase().includes('fastly') },
                    { key: 'x-sucuri-id', name: 'Sucuri' },
                    { key: 'x-sucuri-cache', name: 'Sucuri' },
                    { key: 'x-cdn', name: 'Sucuri', test: v => v.toLowerCase().includes('sucuri') },
                    { key: 'x-cdn', name: 'Incapsula', test: v => v.toLowerCase().includes('incapsula') },
                    { key: 'x-iinfo', name: 'Incapsula' },
                    { key: 'x-cdn', name: 'Amazon CloudFront', test: v => v.toLowerCase().includes('cloudfront') },
                    { key: 'via', name: 'Amazon CloudFront', test: v => v.toLowerCase().includes('cloudfront') },
                    { key: 'x-amz-cf-id', name: 'Amazon CloudFront' },
                    { key: 'x-amz-cf-pop', name: 'Amazon CloudFront' },
                    { key: 'x-cdn', name: 'StackPath', test: v => v.toLowerCase().includes('stackpath') },
                    { key: 'x-cdn', name: 'BunnyCDN', test: v => v.toLowerCase().includes('bunnycdn') },
                    { key: 'server', name: 'BunnyCDN', test: v => v.toLowerCase().includes('bunnycdn') },
                    { key: 'x-cdn', name: 'KeyCDN', test: v => v.toLowerCase().includes('keycdn') },
                    { key: 'server', name: 'KeyCDN', test: v => v.toLowerCase().includes('keycdn') },
                    { key: 'x-cdn', name: 'CDN77', test: v => v.toLowerCase().includes('cdn77') },
                    { key: 'server', name: 'CDN77', test: v => v.toLowerCase().includes('cdn77') }
                ];
    
                cdnProxyIndicators.forEach(indicator => {
                    const value = headers[indicator.key];
                    if (value && (!indicator.test || indicator.test(value))) {
                        results.cdnOrProxy = indicator.name;
                        results.cdnEvidence.push(`${indicator.name} detected via header "${indicator.key}": ${value}`);
                    }
                });
            }
        } catch (e) {
            results.evidence.push('Error processing response: ' + e.message);
        }
    
        // Add nameserver check after initial processing
        checkNameservers(originalUrl, results);
    }

    // New SSL checking function
    function checkSSLcertificate(url, results) {
        try {
            const domain = new URL(url).hostname;
            // Use the same CORS proxy as the main request
            const proxyUrl = 'https://api.allorigins.win/get?url=' + 
                encodeURIComponent(`https://crt.sh/?q=${domain}&output=json`);
    
            $.ajax({
                url: proxyUrl,
                type: 'GET',
                dataType: 'json',
                success: function(response) {
                    try {
                        if (response && response.contents) {
                            const certData = JSON.parse(response.contents);
                            if (Array.isArray(certData) && certData.length > 0) {
                                // Check the most recent certificate
                                const recentCert = certData[0];
                                const issuerInfo = recentCert.issuer_name || '';
                                
                                if (issuerInfo.toLowerCase().includes('cloudflare')) {
                                    results.isCloudflare = true;
                                    results.evidence.push(`Cloudflare SSL Certificate detected (Issuer: ${issuerInfo})`);
                                } else if (issuerInfo.toLowerCase().includes('universal ssl')) {
                                    results.isCloudflare = true;
                                    results.evidence.push('Cloudflare Universal SSL detected');
                                }
                            }
                        }
                    } catch (e) {
                        console.log('Error parsing SSL data:', e);
                    }
                    displayResults(results);
                },
                error: function(xhr, status, error) {
                    console.log('SSL check failed:', error);
                    displayResults(results);
                }
            });
        } catch (e) {
            console.error('SSL check error:', e);
            displayResults(results);
        }
    }

    // New function to check nameservers using Cloudflare DNS-over-HTTPS
    function checkNameservers(url, results) {
        try {
            const domain = new URL(url).hostname;
            const dnsApi = 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(domain) + '&type=NS';
    
            $.ajax({
                url: dnsApi,
                type: 'GET',
                dataType: 'json',
                headers: { 'Accept': 'application/dns-json' },
                success: function(response) {
                    if (response && response.Answer) {
                        const nsList = response.Answer
                            .filter(ans => ans.type === 2 && ans.data)
                            .map(ans => ans.data.toLowerCase());
                        results.nameservers = nsList;
    
                        // Check for Cloudflare or common CDN nameservers
                        nsList.forEach(ns => {
                            if (ns.includes('cloudflare')) {
                                results.isCloudflare = true;
                                results.nsEvidence.push('Cloudflare nameserver detected: ' + ns);
                            } else if (ns.includes('akamai')) {
                                results.cdnOrProxy = 'Akamai';
                                results.nsEvidence.push('Akamai nameserver detected: ' + ns);
                            } else if (ns.includes('fastly')) {
                                results.cdnOrProxy = 'Fastly';
                                results.nsEvidence.push('Fastly nameserver detected: ' + ns);
                            } else if (ns.includes('incapdns')) {
                                results.cdnOrProxy = 'Incapsula';
                                results.nsEvidence.push('Incapsula nameserver detected: ' + ns);
                            } else if (ns.includes('sucuridns')) {
                                results.cdnOrProxy = 'Sucuri';
                                results.nsEvidence.push('Sucuri nameserver detected: ' + ns);
                            } else if (ns.includes('cdns.net')) {
                                results.cdnOrProxy = 'CDNetworks';
                                results.nsEvidence.push('CDNetworks nameserver detected: ' + ns);
                            }
                        });
                    }
                    // Continue to SSL check
                    checkSSLcertificate(url, results);
                },
                error: function(xhr, status, error) {
                    results.nsEvidence.push('Nameserver check failed: ' + error);
                    checkSSLcertificate(url, results);
                }
            });
        } catch (e) {
            results.nsEvidence.push('Nameserver check error: ' + e.message);
            checkSSLcertificate(url, results);
        }
    }

    function parseHeaders(response) {
        const headers = {};
        
        try {
            // Try to extract headers from the response
            if (response.headers) {
                Object.entries(response.headers).forEach(([key, value]) => {
                    headers[key.toLowerCase()] = value;
                });
            }
            else if (response.status?.headers) {
                Object.entries(response.status.headers).forEach(([key, value]) => {
                    headers[key.toLowerCase()] = value;
                });
            }
    
            // Additional Cloudflare cookie checks
            const cookies = headers['set-cookie'] || '';
            if (cookies.toLowerCase().includes('__cf_bm') || cookies.toLowerCase().includes('__cflb')) {
                headers['cloudflare-cookie'] = true;
            }
    
            // Parse HTML content if available
            if (response.contents) {
                const content = response.contents;
                // Create a temporary DOM element to parse the HTML without loading resources
                const parser = new DOMParser();
                const doc = parser.parseFromString(content, 'text/html');
                
                // Check for Cloudflare-specific HTML elements
                const cloudflareScripts = doc.querySelectorAll('script[src*="cloudflare"]');
                const cloudflareCaptcha = doc.querySelector('#cf-challenge-form');
                const cloudflareHoneypot = doc.querySelector('[id^="cf-"]');
    
                if (cloudflareScripts.length > 0) {
                    headers['cloudflare-scripts'] = true;
                }
                if (cloudflareCaptcha) {
                    headers['cloudflare-captcha'] = true;
                }
                if (cloudflareHoneypot) {
                    headers['cloudflare-honeypot'] = true;
                }
            }
        } catch (e) {
            console.error('Error parsing headers:', e);
        }
        
        return headers;
    }

    function displayResults(results) {
        // Clear previous results
        const $results = $('#results');
        $results.empty().removeClass('show');
    
        // Create result HTML
        let html = '<div class="result-item">';
        html += '<div class="result-title">URL Checked:</div>';
        html += '<div class="result-value">' + escapeHtml(results.url) + '</div>';
        html += '</div>';
    
        html += '<div class="result-item">';
        html += '<div class="result-title">Cloudflare Status:</div>';
        if (results.isCloudflare) {
            html += '<div class="result-value cloudflare-detected">✓ Cloudflare Detected</div>';
        } else {
            html += '<div class="result-value cloudflare-not-detected">✗ Cloudflare Not Detected</div>';
        }
        html += '</div>';
    
        // Add CDN/Proxy Status section
        html += '<div class="result-item">';
        html += '<div class="result-title">CDN/Proxy Status:</div>';
        if (results.cdnOrProxy) {
            html += '<div class="result-value cloudflare-detected">✓ ' + escapeHtml(results.cdnOrProxy) + ' Detected</div>';
            if (results.cdnEvidence && results.cdnEvidence.length > 0) {
                html += '<ul class="result-value">';
                results.cdnEvidence.forEach(function(item) {
                    html += '<li>' + escapeHtml(item) + '</li>';
                });
                html += '</ul>';
            }
        } else {
            html += '<div class="result-value cloudflare-not-detected">✗ No CDN/Proxy Detected</div>';
        }
        html += '</div>';
    
        // Add SSL Status section
        html += '<div class="result-item">';
        html += '<div class="result-title">SSL Status:</div>';
        const sslEvidence = results.evidence.find(e =>
            e.includes('Cloudflare SSL Certificate') ||
            e.includes('Universal SSL')
        );
        if (sslEvidence) {
            html += '<div class="result-value cloudflare-detected">✓ ' + escapeHtml(sslEvidence) + '</div>';
        } else {
            html += '<div class="result-value cloudflare-not-detected">✗ No Cloudflare SSL detected</div>';
        }
        html += '</div>';
    
        if (results.evidence && results.evidence.length > 0) {
            html += '<div class="result-item">';
            html += '<div class="result-title">Evidence:</div>';
            html += '<ul class="result-value">';
            results.evidence.forEach(function(item) {
                html += '<li>' + escapeHtml(item) + '</li>';
            });
            html += '</ul>';
            html += '</div>';
        }
    
        // Add Nameserver Status section
        let nsHtml = '<div class="result-item">';
        nsHtml += '<div class="result-title">Nameservers:</div>';
        if (results.nameservers && results.nameservers.length > 0) {
            nsHtml += '<ul class="result-value">';
            results.nameservers.forEach(function(ns) {
                nsHtml += '<li>' + escapeHtml(ns) + '</li>';
            });
            nsHtml += '</ul>';
        } else {
            nsHtml += '<div class="result-value cloudflare-not-detected">No nameservers found</div>';
        }
        nsHtml += '</div>';
    
        // Add Nameserver Evidence section if any
        if (results.nsEvidence && results.nsEvidence.length > 0) {
            nsHtml += '<div class="result-item">';
            nsHtml += '<div class="result-title">Nameserver Evidence:</div>';
            nsHtml += '<ul class="result-value">';
            results.nsEvidence.forEach(function(item) {
                nsHtml += '<li>' + escapeHtml(item) + '</li>';
            });
            nsHtml += '</ul>';
            nsHtml += '</div>';
        }
    
        // Insert nameserver info before SSL section
        html += nsHtml;
    
        if (results.evidence && results.evidence.length > 0) {
            html += '<div class="result-item">';
            html += '<div class="result-title">Evidence:</div>';
            html += '<ul class="result-value">';
            results.evidence.forEach(function(item) {
                html += '<li>' + escapeHtml(item) + '</li>';
            });
            html += '</ul>';
            html += '</div>';
        }
    
        // Add the results to the page
        $results.html(html).addClass('show');
    }

    function showError(message) {
        const $results = $('#results');
        $results.html('<div class="result-item"><div class="result-value" style="color: red;">' + escapeHtml(message) + '</div></div>').addClass('show');
    }

    function showLoading() {
        const $results = $('#results');
        $results.html('<div class="result-item"><div class="result-value loading-value"><span class="loading"></span>Checking website...</div></div>').addClass('show');
    }

    // Helper function to escape HTML
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});