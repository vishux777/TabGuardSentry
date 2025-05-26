// Background service worker for Tab Guard extension
console.log('Tab Guard background script loaded');

// Store for tab monitoring data
let tabMonitoringData = {};
let cpuMonitoringIntervals = {};

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Tab Guard extension installed');
  initializeStorage();
});

// Initialize storage structure
async function initializeStorage() {
  try {
    const result = await chrome.storage.local.get(['tabGuardLogs', 'tabGuardSettings']);
    
    if (!result.tabGuardLogs) {
      await chrome.storage.local.set({
        tabGuardLogs: []
      });
    }
    
    if (!result.tabGuardSettings) {
      await chrome.storage.local.set({
        tabGuardSettings: {
          clipboardMonitoring: true,
          formMonitoring: true,
          cryptoMiningMonitoring: true,
          whitelistedDomains: []
        }
      });
    }
  } catch (error) {
    console.error('Error initializing storage:', error);
  }
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    initializeTabMonitoring(tabId, tab.url);
  }
});

// Listen for tab removal
chrome.tabs.onRemoved.addListener((tabId) => {
  cleanupTabMonitoring(tabId);
});

// Initialize monitoring for a specific tab
function initializeTabMonitoring(tabId, url) {
  tabMonitoringData[tabId] = {
    url: url,
    domain: extractDomain(url),
    startTime: Date.now(),
    suspiciousActivities: [],
    cpuUsage: {
      requestAnimationFrameCalls: 0,
      setIntervalCalls: 0,
      webWorkerCreations: 0,
      lastCheck: Date.now()
    }
  };
  
  // Start CPU monitoring for this tab
  startCpuMonitoring(tabId);
}

// Cleanup monitoring data when tab is closed
function cleanupTabMonitoring(tabId) {
  delete tabMonitoringData[tabId];
  if (cpuMonitoringIntervals[tabId]) {
    clearInterval(cpuMonitoringIntervals[tabId]);
    delete cpuMonitoringIntervals[tabId];
  }
}

// Start CPU usage monitoring for crypto mining detection
function startCpuMonitoring(tabId) {
  // Clear existing interval if any
  if (cpuMonitoringIntervals[tabId]) {
    clearInterval(cpuMonitoringIntervals[tabId]);
  }
  
  cpuMonitoringIntervals[tabId] = setInterval(async () => {
    try {
      // Inject script to check CPU-intensive operations
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: checkCpuIntensiveOperations
      });
    } catch (error) {
      // Tab might be closed or not accessible
      cleanupTabMonitoring(tabId);
    }
  }, 5000); // Check every 5 seconds
}

// Function to be injected for CPU monitoring
function checkCpuIntensiveOperations() {
  // This function runs in the page context
  if (window.tabGuardCpuMonitor) {
    const monitor = window.tabGuardCpuMonitor;
    const now = Date.now();
    const timeDiff = now - monitor.lastCheck;
    
    // Calculate rates per second
    const rafRate = (monitor.rafCalls / timeDiff) * 1000;
    const intervalRate = (monitor.intervalCalls / timeDiff) * 1000;
    const workerRate = (monitor.workerCreations / timeDiff) * 1000;
    
    // Thresholds for suspicious activity
    const RAF_THRESHOLD = 30; // 30 RAF calls per second
    const INTERVAL_THRESHOLD = 10; // 10 interval creations per second
    const WORKER_THRESHOLD = 1; // 1 worker creation per second
    
    if (rafRate > RAF_THRESHOLD || intervalRate > INTERVAL_THRESHOLD || workerRate > WORKER_THRESHOLD) {
      chrome.runtime.sendMessage({
        type: 'CRYPTO_MINING_DETECTED',
        data: {
          url: window.location.href,
          rafRate: rafRate,
          intervalRate: intervalRate,
          workerRate: workerRate,
          timestamp: now
        }
      });
    }
    
    // Reset counters
    monitor.rafCalls = 0;
    monitor.intervalCalls = 0;
    monitor.workerCreations = 0;
    monitor.lastCheck = now;
  }
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.tab) {
    handleSuspiciousActivity(sender.tab.id, message);
  }
});

// Handle suspicious activity reports
async function handleSuspiciousActivity(tabId, message) {
  const activity = {
    type: message.type,
    data: message.data,
    timestamp: Date.now(),
    tabId: tabId
  };
  
  // Store in tab monitoring data
  if (tabMonitoringData[tabId]) {
    tabMonitoringData[tabId].suspiciousActivities.push(activity);
  }
  
  // Store in persistent storage
  try {
    const result = await chrome.storage.local.get(['tabGuardLogs']);
    const logs = result.tabGuardLogs || [];
    logs.push(activity);
    
    // Keep only last 1000 entries
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }
    
    await chrome.storage.local.set({ tabGuardLogs: logs });
    
    // Update badge to show alert
    updateBadge(tabId);
    
    // Show notification for high-risk activities
    if (shouldShowNotification(message.type)) {
      showNotification(activity);
    }
  } catch (error) {
    console.error('Error storing activity log:', error);
  }
}

// Update extension badge
function updateBadge(tabId) {
  if (tabMonitoringData[tabId] && tabMonitoringData[tabId].suspiciousActivities.length > 0) {
    chrome.action.setBadgeText({
      text: '!',
      tabId: tabId
    });
    chrome.action.setBadgeBackgroundColor({
      color: '#ff4444',
      tabId: tabId
    });
  }
}

// Check if notification should be shown
function shouldShowNotification(activityType) {
  const highRiskActivities = ['CRYPTO_MINING_DETECTED', 'AUTO_FORM_SUBMISSION'];
  return highRiskActivities.includes(activityType);
}

// Show notification for suspicious activity
function showNotification(activity) {
  const messages = {
    'CRYPTO_MINING_DETECTED': 'Potential crypto mining detected',
    'CLIPBOARD_ACCESS': 'Clipboard access detected',
    'AUTO_FORM_SUBMISSION': 'Automatic form submission detected'
  };
  
  console.log(`Tab Guard Alert: ${messages[activity.type]} on ${activity.data.url}`);
}

// Utility function to extract domain from URL
function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return url;
  }
}

// API for popup to get monitoring data
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'GET_MONITORING_DATA') {
    sendResponse({
      tabData: tabMonitoringData,
      success: true
    });
  } else if (message.action === 'GET_ACTIVITY_LOGS') {
    chrome.storage.local.get(['tabGuardLogs']).then(result => {
      sendResponse({
        logs: result.tabGuardLogs || [],
        success: true
      });
    });
    return true; // Keep message channel open for async response
  }
});