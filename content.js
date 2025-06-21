// Tab Guard Advanced Content Script
console.log('Tab Guard v3.0 - Content script loaded');

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
  monitorRedirects();
  monitorPopups();
  detectKeyloggers();
  
  console.log('Tab Guard monitoring initialized for:', window.location.href);
}

function initializeCpuMonitoring() {
  window.tabGuardCpuMonitor = {
    rafCalls: 0,
    intervalCalls: 0,
    workerCreations: 0,
    lastCheck: Date.now()
  };
  
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
  
  setInterval(() => {
    const now = Date.now();
    const timeDiff = now - window.tabGuardCpuMonitor.lastCheck;
    const rafRate = window.tabGuardCpuMonitor.rafCalls / (timeDiff / 1000);
    
    if (rafRate > 30) {
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'Abnormally high requestAnimationFrame usage',
        rafRate: rafRate,
        url: window.location.href,
        riskScore: 55
      });
    }
    
    window.tabGuardCpuMonitor.rafCalls = 0;
    window.tabGuardCpuMonitor.lastCheck = now;
  }, 5000);
}

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

function detectAdvancedThreats() {
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
  
  let keyStrokeCount = 0;
  let keyStrokeTimer = null;
  
  document.addEventListener('keydown', () => {
    keyStrokeCount++;
    
    if (keyStrokeTimer) {
      clearTimeout(keyStrokeTimer);
    }
    
    keyStrokeTimer = setTimeout(() => {
      if (keyStrokeCount > 50) {
        reportSuspiciousActivity('EXCESSIVE_KEYSTROKE_MONITORING', {
          reason: 'Abnormally high keystroke monitoring detected',
          keyStrokes: keyStrokeCount,
          url: window.location.href,
          riskScore: 65
        });
      }
      keyStrokeCount = 0;
    }, 10000);
  });
}

function monitorRedirects() {
  let redirectCount = 0;
  const originalAssign = window.location.assign;
  const originalReplace = window.location.replace;
  
  window.location.assign = function(url) {
    redirectCount++;
    if (redirectCount > 3) {
      reportSuspiciousActivity('EXCESSIVE_REDIRECTS', {
        reason: 'Multiple redirects detected',
        targetUrl: url,
        redirectCount: redirectCount,
        url: window.location.href,
        riskScore: 55
      });
    }
    return originalAssign.call(this, url);
  };
  
  window.location.replace = function(url) {
    redirectCount++;
    if (redirectCount > 3) {
      reportSuspiciousActivity('EXCESSIVE_REDIRECTS', {
        reason: 'Multiple redirects detected',
        targetUrl: url,
        redirectCount: redirectCount,
        url: window.location.href,
        riskScore: 55
      });
    }
    return originalReplace.call(this, url);
  };
}

function monitorPopups() {
  const originalOpen = window.open;
  let popupCount = 0;
  
  window.open = function(url, name, specs, replace) {
    popupCount++;
    
    reportSuspiciousActivity('POPUP_DETECTED', {
      reason: 'Popup window opened',
      targetUrl: url,
      popupCount: popupCount,
      url: window.location.href,
      riskScore: popupCount > 2 ? 60 : 30
    });
    
    return originalOpen.call(this, url, name, specs, replace);
  };
}

function detectKeyloggers() {
  let suspiciousKeyEvents = 0;
  const keyEventPatterns = [];
  
  document.addEventListener('keydown', (event) => {
    keyEventPatterns.push({
      key: event.key,
      timestamp: Date.now(),
      target: event.target.tagName
    });
    
    // Keep only recent events
    const fiveMinutesAgo = Date.now() - 300000;
    const recentEvents = keyEventPatterns.filter(e => e.timestamp > fiveMinutesAgo);
    
    // Check for suspicious patterns
    if (recentEvents.length > 200) {
      suspiciousKeyEvents++;
      
      if (suspiciousKeyEvents > 3) {
        reportSuspiciousActivity('POTENTIAL_KEYLOGGER', {
          reason: 'Excessive keyboard event monitoring detected',
          eventCount: recentEvents.length,
          url: window.location.href,
          riskScore: 70
        });
        suspiciousKeyEvents = 0;
      }
    }
  });
}

function reportSuspiciousActivity(type, data) {
  try {
    chrome.runtime.sendMessage({
      action: 'REPORT_SUSPICIOUS_ACTIVITY',
      data: {
        type: type,
        timestamp: Date.now(),
        ...data
      }
    }).catch(error => {
      console.error('Failed to report suspicious activity:', error);
    });
  } catch (error) {
    console.error('Error reporting suspicious activity:', error);
  }
}

// Performance monitoring
window.addEventListener('load', () => {
  const perfData = performance.getEntriesByType('navigation')[0];
  if (perfData && perfData.loadEventEnd - perfData.loadEventStart > 10000) {
    reportSuspiciousActivity('SLOW_PAGE_LOAD', {
      reason: 'Unusually slow page load detected',
      loadTime: perfData.loadEventEnd - perfData.loadEventStart,
      url: window.location.href,
      riskScore: 25
    });
  }
});

// Check for mining indicators in page content
document.addEventListener('DOMContentLoaded', () => {
  const bodyText = document.body.textContent || '';
  if (/mining|crypto|monero|bitcoin|hash rate/i.test(bodyText)) {
    reportSuspiciousActivity('CRYPTO_CONTENT_DETECTED', {
      reason: 'Cryptocurrency-related content detected',
      url: window.location.href,
      riskScore: 20
    });
  }
});
