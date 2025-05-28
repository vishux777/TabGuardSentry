// Tab Guard Advanced Content Script
console.log('Tab Guard v3.0 - Content script loaded');

// Prevent multiple injections
if (window.tabGuardInjected) {
  console.log('Tab Guard already active on this page');
} else {
  window.tabGuardInjected = true;
  initializeTabGuard();
}

function initializeTabGuard() {
  initializeCpuMonitoring();
  monitorClipboardAccess();
  monitorFormSubmissions();
  monitorNetworkRequests();
  monitorPermissionRequests();
  monitorDownloads();
  detectAdvancedThreats();
  
  console.log('Tab Guard monitoring initialized for:', window.location.href);
}

// Enhanced CPU monitoring for crypto mining detection
function initializeCpuMonitoring() {
  window.tabGuardCpuMonitor = {
    rafCalls: 0,
    intervalCalls: 0,
    workerCreations: 0,
    lastCheck: Date.now()
  };
  
  // Override requestAnimationFrame
  const originalRAF = window.requestAnimationFrame;
  window.requestAnimationFrame = function(callback) {
    window.tabGuardCpuMonitor.rafCalls++;
    
    const callbackStr = callback.toString();
    if (/hash|mine|crypto|sha256|scrypt/i.test(callbackStr)) {
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'Hashing function in requestAnimationFrame',
        evidence: callbackStr.substring(0, 100),
        url: window.location.href,
        riskScore: 60
      });
    }
    
    return originalRAF.call(this, callback);
  };
  
  // Override setInterval
  const originalSetInterval = window.setInterval;
  window.setInterval = function(callback, delay) {
    window.tabGuardCpuMonitor.intervalCalls++;
    
    const callbackStr = callback.toString();
    if (delay < 50 && /hash|mine|worker|crypto/i.test(callbackStr)) {
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'High-frequency interval with mining patterns',
        delay: delay,
        evidence: callbackStr.substring(0, 100),
        url: window.location.href,
        riskScore: 70
      });
    }
    
    return originalSetInterval.call(this, callback, delay);
  };
  
  // Override Worker creation
  const originalWorker = window.Worker;
  if (originalWorker) {
    window.Worker = function(scriptURL, options) {
      window.tabGuardCpuMonitor.workerCreations++;
      
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'Web Worker creation detected',
        scriptURL: scriptURL,
        options: options,
        url: window.location.href,
        riskScore: 50
      });
      
      return new originalWorker(scriptURL, options);
    };
  }
  
  // Monitor WebAssembly (common in crypto miners)
  if (window.WebAssembly) {
    const originalInstantiate = WebAssembly.instantiate;
    WebAssembly.instantiate = function(bytes, importObject) {
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'WebAssembly instantiation detected',
        size: bytes.byteLength || 'unknown',
        url: window.location.href,
        riskScore: 80
      });
      return originalInstantiate.call(this, bytes, importObject);
    };
  }
}

// Enhanced clipboard monitoring
function monitorClipboardAccess() {
  if (navigator.clipboard) {
    if (navigator.clipboard.readText) {
      const originalReadText = navigator.clipboard.readText;
      navigator.clipboard.readText = function() {
        reportSuspiciousActivity('CLIPBOARD_ACCESS', {
          action: 'read',
          method: 'navigator.clipboard.readText',
          url: window.location.href,
          userInteraction: document.hasFocus(),
          riskScore: 30
        });
        return originalReadText.apply(this, arguments);
      };
    }
    
    if (navigator.clipboard.writeText) {
      const originalWriteText = navigator.clipboard.writeText;
      navigator.clipboard.writeText = function(text) {
        reportSuspiciousActivity('CLIPBOARD_ACCESS', {
          action: 'write',
          method: 'navigator.clipboard.writeText',
          textLength: text ? text.length : 0,
          preview: text ? text.substring(0, 20) : '',
          url: window.location.href,
          riskScore: 25
        });
        return originalWriteText.apply(this, arguments);
      };
    }
  }
  
  // Monitor legacy clipboard access
  const originalExecCommand = document.execCommand;
  document.execCommand = function(command, showUI, value) {
    if (['copy', 'cut', 'paste'].includes(command)) {
      reportSuspiciousActivity('CLIPBOARD_ACCESS', {
        action: command,
        method: 'document.execCommand',
        value: value,
        url: window.location.href,
        riskScore: 20
      });
    }
    return originalExecCommand.apply(this, arguments);
  };
}

// Enhanced form submission monitoring
function monitorFormSubmissions() {
  let userInteractionDetected = false;
  let lastUserInteraction = 0;
  
  const userEvents = ['click', 'keydown', 'keyup', 'mousedown', 'mouseup', 'touchstart', 'touchend'];
  
  userEvents.forEach(eventType => {
    document.addEventListener(eventType, () => {
      userInteractionDetected = true;
      lastUserInteraction = Date.now();
    }, true);
  });
  
  // Override form submit
  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    const timeSinceLastInteraction = Date.now() - lastUserInteraction;
    const formData = new FormData(this);
    const fieldCount = Array.from(formData.keys()).length;
    
    const suspiciousActivity = {
      formAction: this.action || window.location.href,
      formMethod: this.method || 'GET',
      fieldCount: fieldCount,
      timeSinceLastInteraction: timeSinceLastInteraction,
      url: window.location.href,
      hasPasswordField: this.querySelector('input[type="password"]') !== null,
      hasEmailField: this.querySelector('input[type="email"]') !== null
    };
    
    if (!userInteractionDetected || timeSinceLastInteraction > 2000) {
      reportSuspiciousActivity('AUTO_FORM_SUBMISSION', {
        ...suspiciousActivity,
        reason: 'Form submitted without user interaction',
        riskScore: 60
      });
    }
    
    // Check for credential harvesting
    if (suspiciousActivity.hasPasswordField && suspiciousActivity.hasEmailField) {
      const domain = new URL(this.action || window.location.href).hostname;
      if (domain !== window.location.hostname) {
        reportSuspiciousActivity('PHISHING_ATTEMPT', {
          ...suspiciousActivity,
          reason: 'Credentials being sent to external domain',
          targetDomain: domain,
          riskScore: 90
        });
      }
    }
    
    return originalSubmit.apply(this, arguments);
  };
  
  // Monitor submit events
  document.addEventListener('submit', (event) => {
    const timeSinceLastInteraction = Date.now() - lastUserInteraction;
    
    if (!userInteractionDetected || timeSinceLastInteraction > 2000) {
      reportSuspiciousActivity('AUTO_FORM_SUBMISSION', {
        formAction: event.target.action || window.location.href,
        formMethod: event.target.method || 'GET',
        timeSinceLastInteraction: timeSinceLastInteraction,
        eventType: 'submit_event',
        url: window.location.href,
        riskScore: 50
      });
    }
  }, true);
}

// Monitor network requests
function monitorNetworkRequests() {
  const originalFetch = window.fetch;
  window.fetch = function(resource, options) {
    const url = resource.toString();
    
    if (/mining|crypto|hash|stratum|malware/i.test(url)) {
      reportSuspiciousActivity('SUSPICIOUS_NETWORK_REQUEST', {
        url: url,
        method: options?.method || 'GET',
        reason: 'Suspicious URL pattern detected',
        initiator: window.location.href,
        riskScore: 70
      });
    }
    
    return originalFetch.apply(this, arguments);
  };
  
  const originalXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    if (/mining|crypto|hash|stratum|malware/i.test(url)) {
      reportSuspiciousActivity('SUSPICIOUS_NETWORK_REQUEST', {
        url: url,
        method: method,
        reason: 'Suspicious XHR request',
        initiator: window.location.href,
        riskScore: 65
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
        timestamp: Date.now(),
        riskScore: 30
      });
      return originalQuery.apply(this, arguments);
    };
  }
  
  if (navigator.geolocation) {
    const originalGetCurrentPosition = navigator.geolocation.getCurrentPosition;
    navigator.geolocation.getCurrentPosition = function(success, error, options) {
      reportSuspiciousActivity('PERMISSION_REQUEST', {
        permission: 'geolocation',
        method: 'getCurrentPosition',
        url: window.location.href,
        riskScore: 40
      });
      return originalGetCurrentPosition.apply(this, arguments);
    };
  }
  
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
    navigator.mediaDevices.getUserMedia = function(constraints) {
      reportSuspiciousActivity('PERMISSION_REQUEST', {
        permission: 'media',
        constraints: constraints,
        url: window.location.href,
        riskScore: 50
      });
      return originalGetUserMedia.apply(this, arguments);
    };
  }
}

// Monitor downloads
function monitorDownloads() {
  document.addEventListener('click', (event) => {
    const element = event.target.closest('a');
    if (element && element.href) {
      const url = element.href;
      const filename = url.split('/').pop() || '';
      const extension = filename.split('.').pop()?.toLowerCase();
      
      const suspiciousExtensions = ['exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js'];
      
      if (suspiciousExtensions.includes(extension)) {
        reportSuspiciousActivity('SUSPICIOUS_DOWNLOAD', {
          url: url,
          filename: filename,
          extension: extension,
          reason: 'Potentially dangerous file type',
          initiator: window.location.href,
          riskScore: 75
        });
      }
    }
  }, true);
}

// Detect advanced threats
function detectAdvancedThreats() {
  // Monitor for malicious scripts
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'SCRIPT') {
            const scriptContent = node.textContent || node.innerHTML;
            if (/eval\(|atob\(|fromCharCode/i.test(scriptContent)) {
              reportSuspiciousActivity('MALICIOUS_SCRIPT', {
                reason: 'Obfuscated script detected',
                evidence: scriptContent.substring(0, 100),
                url: window.location.href,
                riskScore: 80
              });
            }
          }
          
          // Check for iframe injections
          if (node.tagName === 'IFRAME') {
            const src = node.src;
            if (src && new URL(src).hostname !== window.location.hostname) {
              reportSuspiciousActivity('SUSPICIOUS_IFRAME', {
                src: src,
                reason: 'External iframe injection',
                url: window.location.href,
                riskScore: 45
              });
            }
          }
        }
      });
    });
  });
  
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
  
  // Monitor for CSS-based attacks
  document.addEventListener('DOMContentLoaded', () => {
    const styles = document.querySelectorAll('style');
    styles.forEach(style => {
      if (/expression\(|javascript:|@import/i.test(style.textContent)) {
        reportSuspiciousActivity('MALICIOUS_CSS', {
          reason: 'Potentially malicious CSS detected',
          evidence: style.textContent.substring(0, 100),
          url: window.location.href,
          riskScore: 60
        });
      }
    });
  });
}

// Report suspicious activity to background script
function reportSuspiciousActivity(type, data) {
  try {
    chrome.runtime.sendMessage({
      type: type,
      data: {
        ...data,
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        referrer: document.referrer
      }
    });
  } catch (error) {
    console.error('Failed to report suspicious activity:', error);
  }
}

// Expose monitoring status for debugging
window.tabGuardStatus = {
  version: '3.0.0',
  active: true,
  monitoringTypes: [
    'CPU Mining Detection',
    'Clipboard Protection',
    'Form Monitoring',
    'Network Monitoring',
    'Permission Tracking',
    'Download Protection',
    'Advanced Threat Detection'
  ]
};