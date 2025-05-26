  HTMLFormElement.prototype.submit = function() {
    const timeSinceLastInteraction = Date.now() - lastUserInteraction;
    const formData = new FormData(this);
    const fieldCount = Array.from(formData.keys()).length;
    
    const suspiciousActivity = {
      formAction: this.action || window.location.href,
      formMethod: this.method || 'GET',
      fieldCount: fieldCount,
      timeSinceLastInteraction: timeSinceLastInteraction,
      userInteractionCount: formInteractionCount,
      url: window.location.href,
      hasPasswordField: this.querySelector('input[type="password"]') !== null,
      hasEmailField: this.querySelector('input[type="email"]') !== null
    };
    
    // Enhanced suspicious activity detection
    if (!userInteractionDetected || 
        timeSinceLastInteraction > 3000 || 
        formInteractionCount === 0) {
      reportSuspiciousActivity('AUTO_FORM_SUBMISSION', {
        ...suspiciousActivity,
        reason: 'Form submitted without user interaction'
      });
    }
    
    // Check for credential harvesting
    if (suspiciousActivity.hasPasswordField && suspiciousActivity.hasEmailField) {
      const domain = new URL(this.action || window.location.href).hostname;
      if (domain !== window.location.hostname) {
        reportSuspiciousActivity('PHISHING_ATTEMPT', {
          ...suspiciousActivity,
          reason: 'Credentials being sent to external domain',
          targetDomain: domain
        });
      }
    }
    
    return originalSubmit.apply(this, arguments);
  };
  
  // Monitor submit events
  document.addEventListener('submit', (event) => {
    const timeSinceLastInteraction = Date.now() - lastUserInteraction;
    
    if (!userInteractionDetected || timeSinceLastInteraction > 3000) {
      reportSuspiciousActivity('AUTO_FORM_SUBMISSION', {
        formAction: event.target.action || window.location.href,
        formMethod: event.target.method || 'GET',
        timeSinceLastInteraction: timeSinceLastInteraction,
        eventType: 'submit_event',
        url: window.location.href
      });
    }
  }, true);
}

// Monitor network requests
function monitorNetworkRequests() {
  // Monitor fetch requests
  const originalFetch = window.fetch;
  window.fetch = function(resource, options) {
    const url = resource.toString();
    
    // Check for suspicious URLs
    if (/mining|crypto|hash|stratum/i.test(url)) {
      reportSuspiciousActivity('SUSPICIOUS_NETWORK_REQUEST', {
        url: url,
        method: options?.method || 'GET',
        reason: 'Potential mining-related request',
        initiator: window.location.href
      });
    }
    
    return originalFetch.apply(this, arguments);
  };
  
  // Monitor XMLHttpRequest
  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    if (/mining|crypto|hash|stratum|malware/i.test(url)) {
      reportSuspiciousActivity('SUSPICIOUS_NETWORK_REQUEST', {
        url: url,
        method: method,
        reason: 'Suspicious XHR request',
        initiator: window.location.href
      });
    }
    
    return originalXHROpen.apply(this, arguments);
  };
}

// Monitor permission requests
function monitorPermissionRequests() {
  if (navigator.permissions) {
    const originalQuery = navigator.permissions.query;
    navigator.permissions.query = function(permissionDesc) {
      reportSuspiciousActivity('PERMISSION_REQUEST', {
        permission: permissionDesc.name,
        url: window.location.href,
        timestamp: Date.now()
      });
      return originalQuery.apply(this, arguments);
    };
  }
  
  // Monitor geolocation requests
  if (navigator.geolocation) {
    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
    navigator.geolocation.getCurrentPosition = function(success, error, options) {
      reportSuspiciousActivity('PERMISSION_REQUEST', {
        permission: 'geolocation',
        method: 'getCurrentPosition',
        url: window.location.href
      });
      return originalGetCurrentPosition.apply(this, arguments);
    };
  }
  
  // Monitor camera/microphone access
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
    navigator.mediaDevices.getUserMedia = function(constraints) {
      reportSuspiciousActivity('PERMISSION_REQUEST', {
        permission: 'media',
        constraints: constraints,
        url: window.location.href
      });
      return originalGetUserMedia.apply(this, arguments);
    };
  }
}

// Monitor downloads
function monitorDownloads() {
  // Monitor programmatic downloads
  document.addEventListener('click', (event) => {
    const target = event.target;
    if (target.tagName === 'A' && target.download) {
      const suspiciousExtensions = /\.(exe|bat|cmd|scr|pif|com|jar|zip|rar)$/i;
      if (suspiciousExtensions.test(target.href)) {
        reportSuspiciousActivity('SUSPICIOUS_DOWNLOAD', {
          url: target.href,
          filename: target.download,
          reason: 'Potentially dangerous file extension',
          initiator: window.location.href
        });
      }
    }
  });
  
  // Monitor blob URL creation (often used for malicious downloads)
  const originalCreateObjectURL = URL.createObjectURL;
  URL.createObjectURL = function(object) {
    if (object instanceof Blob) {
      reportSuspiciousActivity('SUSPICIOUS_DOWNLOAD', {
        type: 'blob_creation',
        size: object.size,
        mimeType: object.type,
        reason: 'Blob URL created for download',
        url: window.location.href
      });
    }
    return originalCreateObjectURL.apply(this, arguments);
  };
}

// Monitor redirects
function monitorRedirects() {
  // Monitor location changes
  const originalReplace = window.location.replace;
  window.location.replace = function(url) {
    reportSuspiciousActivity('REDIRECT_ATTEMPT', {
      targetUrl: url,
      method: 'location.replace',
      currentUrl: window.location.href
    });
    return originalReplace.apply(this, arguments);
  };
  
  // Monitor history manipulation
  const originalPushState = history.pushState;
  history.pushState = function(state, title, url) {
    if (url && url !== window.location.href) {
      reportSuspiciousActivity('REDIRECT_ATTEMPT', {
        targetUrl: url,
        method: 'history.pushState',
        currentUrl: window.location.href
      });
    }
    return originalPushState.apply(this, arguments);
  };
}

// Monitor popup attempts
function monitorPopups() {
  const originalOpen = window.open;
  window.open = function(url, name, features) {
    reportSuspiciousActivity('POPUP_ATTEMPT', {
      url: url,
      name: name,
      features: features,
      initiator: window.location.href
    });
    return originalOpen.apply(this, arguments);
  };
}

// Monitor keylogger attempts
function monitorKeyloggers() {
  let keyEventCount = 0;
  let keyEventStartTime = Date.now();
  
  document.addEventListener('keydown', (event) => {
    keyEventCount++;
    
    // Check for excessive key event monitoring
    const now = Date.now();
    if (now - keyEventStartTime > 60000) { // Every minute
      if (keyEventCount > 1000) { // Suspicious amount of key monitoring
        reportSuspiciousActivity('KEYLOGGER_DETECTED', {
          keyEventCount: keyEventCount,
          timeWindow: 60000,
          url: window.location.href
        });
      }
      keyEventCount = 0;
      keyEventStartTime = now;
    }
  });
}

// Monitor screen capture attempts
function monitorScreenCapture() {
  if (navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia) {
    const originalGetDisplayMedia = navigator.mediaDevices.getDisplayMedia;
    navigator.mediaDevices.getDisplayMedia = function(constraints) {
      reportSuspiciousActivity('SCREEN_CAPTURE_ATTEMPT', {
        constraints: constraints,
        url: window.location.href
      });
      return originalGetDisplayMedia.apply(this, arguments);
    };
  }
}

// Enhanced suspicious activity reporting
function reportSuspiciousActivity(type, data) {
  try {
    const enhancedData = {
      ...data,
      timestamp: Date.now(),
      userAgent: navigator.userAgent,
      domain: window.location.hostname,
      referrer: document.referrer,
      cookieEnabled: navigator.cookieEnabled,
      language: navigator.language,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}`,
      windowSize: `${window.innerWidth}x${window.innerHeight}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    
    chrome.runtime.sendMessage({
      type: type,
      data: enhancedData
    });
  } catch (error) {
    console.error('Error reporting suspicious activity:', error);
  }
}

// Enhanced pattern detection for known threats
function detectAdvancedThreats() {
  const pageContent = document.documentElement.innerHTML.toLowerCase();
  const scripts = document.getElementsByTagName('script');
  
  // Advanced crypto mining patterns
  const cryptoPatterns = [
    /coinhive|crypto-loot|cryptonight|monero|webassembly.*mining/gi,
    /stratum\+tcp|mining.*pool|hashrate|cpu.*miner/gi,
    /sha256|scrypt|x11|equihash/gi
  ];
  
  // Phishing patterns
  const phishingPatterns = [
    /verify.*account.*suspended|urgent.*action.*required/gi,
    /click.*here.*immediately|account.*verification/gi,
    /security.*alert.*login/gi
  ];
  
  // Malicious script patterns
  const maliciousPatterns = [
    /eval\(.*atob|document\.write.*unescape/gi,
    /fromcharcode.*join|string\.fromcharcode/gi,
    /base64.*decode|atob.*eval/gi
  ];
  
  // Check page content
  [...cryptoPatterns, ...phishingPatterns, ...maliciousPatterns].forEach(pattern => {
    const matches = pageContent.match(pattern);
    if (matches && matches.length > 0) {
      reportSuspiciousActivity('MALICIOUS_CONTENT_DETECTED', {
        pattern: pattern.toString(),
        matches: matches.slice(0, 5), // First 5 matches
        location: 'page_content',
        url: window.location.href
      });
    }
  });
  
  // Check individual scripts
  Array.from(scripts).forEach((script, index) => {
    const scriptContent = script.textContent || script.innerHTML;
    const scriptSrc = script.src;
    
    if (scriptContent) {
      maliciousPatterns.forEach(pattern => {
        if (pattern.test(scriptContent)) {
          reportSuspiciousActivity('MALICIOUS_SCRIPT', {
            pattern: pattern.toString(),
            scriptIndex: index,
            scriptSrc: scriptSrc || 'inline',
            evidence: scriptContent.substring(0, 200),
            url: window.location.href
          });
        }
      });
    }
    
    if (scriptSrc) {
      cryptoPatterns.forEach(pattern => {
        if (pattern.test(scriptSrc)) {
          reportSuspiciousActivity('MALICIOUS_SCRIPT', {
            pattern: pattern.toString(),
            scriptSrc: scriptSrc,
            reason: 'Suspicious script source',
            url: window.location.href
          });
        }
      });
    }
  });
}

// Run initial threat detection
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', detectAdvancedThreats);
} else {
  detectAdvancedThreats();
}

// Enhanced mutation observer for dynamic content
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        if (node.tagName === 'SCRIPT') {
          detectAdvancedThreats();
        }
        
        // Check for suspicious iframes
        if (node.tagName === 'IFRAME') {
          const src = node.src;
          if (src && (/mining|crypto|malware/i.test(src) || 
                     new URL(src).hostname !== window.location.hostname)) {
            reportSuspiciousActivity('SUSPICIOUS_IFRAME', {
              src: src,
              reason: 'Cross-origin or suspicious iframe',
              url: window.location.href
            });
          }
        }
        
        // Check for hidden elements (often used in attacks)
        if (node.style && (node.style.display === 'none' || 
                          node.style.visibility === 'hidden' ||
                          node.style.opacity === '0')) {
          const content = node.textContent || node.innerHTML;
          if (content && content.length > 100) {
            reportSuspiciousActivity('HIDDEN_CONTENT', {
              tagName: node.tagName,
              contentLength: content.length,
              preview: content.substring(0, 100),
              url: window.location.href
            });
          }
        }
      }
    });
  });
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true,
  attributes: true,
  attributeFilter: ['src', 'href', 'style']
});

// Performance monitoring for mining detection
let performanceEntries = [];
setInterval(() => {
  const entries = performance.getEntriesByType('measure');
  const cpuIntensive = entries.filter(entry => entry.duration > 100);
  
  if (cpuIntensive.length > 10) {
    reportSuspiciousActivity('HIGH_CPU_USAGE', {
      intensiveOperations: cpuIntensive.length,
      totalDuration: cpuIntensive.reduce((sum, entry) => sum + entry.duration, 0),
      url: window.location.href
    });
  }
}, 30000); // Check every 30 seconds