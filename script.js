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
            evidence: []
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
            }
        } catch (e) {
            results.evidence.push('Error processing response: ' + e.message);
        }

        // Add SSL check after initial processing
        checkSSLcertificate(originalUrl, results);
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