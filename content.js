// Content script for Tab Guard extension
console.log('Tab Guard content script loaded on:', window.location.href);

// Prevent multiple injections
if (window.tabGuardInjected) {
  console.log('Tab Guard already injected, skipping');
} else {
  window.tabGuardInjected = true;
  
  // Initialize monitoring
  initializeTabGuard();
}

function initializeTabGuard() {
  // Initialize CPU monitoring
  initializeCpuMonitoring();
  
  // Monitor clipboard access
  monitorClipboardAccess();
  
  // Monitor form submissions
  monitorFormSubmissions();
  
  console.log('Tab Guard monitoring initialized');
}

// Initialize CPU monitoring for crypto mining detection
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
    return originalRAF.call(this, callback);
  };
  
  // Override setInterval
  const originalSetInterval = window.setInterval;
  window.setInterval = function(callback, delay) {
    window.tabGuardCpuMonitor.intervalCalls++;
    return originalSetInterval.call(this, callback, delay);
  };
  
  // Override setTimeout for high-frequency calls
  const originalSetTimeout = window.setTimeout;
  let setTimeoutCallCount = 0;
  let setTimeoutLastReset = Date.now();
  
  window.setTimeout = function(callback, delay) {
    const now = Date.now();
    
    // Reset counter every second
    if (now - setTimeoutLastReset > 1000) {
      setTimeoutCallCount = 0;
      setTimeoutLastReset = now;
    }
    
    setTimeoutCallCount++;
    
    // If more than 50 setTimeout calls per second with short delays, it's suspicious
    if (setTimeoutCallCount > 50 && (delay === undefined || delay < 100)) {
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'High frequency setTimeout calls',
        callCount: setTimeoutCallCount,
        url: window.location.href
      });
    }
    
    return originalSetTimeout.call(this, callback, delay);
  };
  
  // Override Worker constructor
  const originalWorker = window.Worker;
  if (originalWorker) {
    window.Worker = function(scriptURL, options) {
      window.tabGuardCpuMonitor.workerCreations++;
      
      reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
        reason: 'Web Worker creation detected',
        scriptURL: scriptURL,
        url: window.location.href
      });
      
      return new originalWorker(scriptURL, options);
    };
  }
}

// Monitor clipboard access
function monitorClipboardAccess() {
  // Override clipboard read operations
  if (navigator.clipboard && navigator.clipboard.readText) {
    const originalReadText = navigator.clipboard.readText;
    navigator.clipboard.readText = function() {
      reportSuspiciousActivity('CLIPBOARD_ACCESS', {
        action: 'read',
        url: window.location.href
      });
      return originalReadText.apply(this, arguments);
    };
  }
  
  // Override clipboard write operations
  if (navigator.clipboard && navigator.clipboard.writeText) {
    const originalWriteText = navigator.clipboard.writeText;
    navigator.clipboard.writeText = function(text) {
      reportSuspiciousActivity('CLIPBOARD_ACCESS', {
        action: 'write',
        url: window.location.href,
        textLength: text ? text.length : 0
      });
      return originalWriteText.apply(this, arguments);
    };
  }
  
  // Monitor legacy clipboard access through execCommand
  const originalExecCommand = document.execCommand;
  document.execCommand = function(command, showUI, value) {
    if (command === 'copy' || command === 'cut' || command === 'paste') {
      reportSuspiciousActivity('CLIPBOARD_ACCESS', {
        action: command,
        method: 'execCommand',
        url: window.location.href
      });
    }
    return originalExecCommand.apply(this, arguments);
  };
}

// Monitor form submissions
function monitorFormSubmissions() {
  let userInteractionDetected = false;
  let lastUserInteraction = 0;
  
  // Track user interactions
  const userInteractionEvents = ['click', 'keydown', 'keyup', 'mousedown', 'mouseup', 'touchstart', 'touchend'];
  
  userInteractionEvents.forEach(eventType => {
    document.addEventListener(eventType, () => {
      userInteractionDetected = true;
      lastUserInteraction = Date.now();
    }, true);
  });
  
  // Override form submit method
  const originalSubmit = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function() {
    const timeSinceLastInteraction = Date.now() - lastUserInteraction;
    
    // If form is submitted without recent user interaction (within 2 seconds), it's suspicious
    if (!userInteractionDetected || timeSinceLastInteraction > 2000) {
      reportSuspiciousActivity('AUTO_FORM_SUBMISSION', {
        formAction: this.action || 'undefined',
        formMethod: this.method || 'GET',
        timeSinceLastInteraction: timeSinceLastInteraction,
        url: window.location.href
      });
    }
    
    return originalSubmit.apply(this, arguments);
  };
  
  // Monitor submit events
  document.addEventListener('submit', (event) => {
    const timeSinceLastInteraction = Date.now() - lastUserInteraction;
    
    // Check if this is an automated submission
    if (!userInteractionDetected || timeSinceLastInteraction > 2000) {
      reportSuspiciousActivity('AUTO_FORM_SUBMISSION', {
        formAction: event.target.action || 'undefined',
        formMethod: event.target.method || 'GET',
        timeSinceLastInteraction: timeSinceLastInteraction,
        eventType: 'submit_event',
        url: window.location.href
      });
    }
  }, true);
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
        domain: window.location.hostname
      }
    });
  } catch (error) {
    console.error('Error reporting suspicious activity:', error);
  }
}

// Monitor for known crypto mining patterns
function detectKnownMiningPatterns() {
  // Check for common mining libraries in scripts
  const scripts = document.getElementsByTagName('script');
  const suspiciousPatterns = [
    /coinhive/i,
    /cryptonight/i,
    /monero/i,
    /webassembly.*mining/i,
    /wasm.*hash/i
  ];
  
  Array.from(scripts).forEach(script => {
    const scriptContent = script.textContent || script.innerHTML;
    const scriptSrc = script.src;
    
    suspiciousPatterns.forEach(pattern => {
      if ((scriptContent && pattern.test(scriptContent)) || 
          (scriptSrc && pattern.test(scriptSrc))) {
        reportSuspiciousActivity('CRYPTO_MINING_DETECTED', {
          reason: 'Known mining pattern detected',
          pattern: pattern.toString(),
          scriptSrc: scriptSrc || 'inline',
          url: window.location.href
        });
      }
    });
  });
}

// Run initial pattern detection
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', detectKnownMiningPatterns);
} else {
  detectKnownMiningPatterns();
}

// Monitor for dynamic script additions
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      if (node.tagName === 'SCRIPT') {
        detectKnownMiningPatterns();
      }
    });
  });
});

observer.observe(document.documentElement, {
  childList: true,
  subtree: true
});