// Advanced Background service worker for Tab Guard extension
console.log('Tab Guard Advanced background script loaded');

// Store for tab monitoring data
let tabMonitoringData = {};
let cpuMonitoringIntervals = {};
let networkMonitoringData = {};
let threatDatabase = new Set();
let realTimeStats = {
  threatsBlocked: 0,
  tabsMonitored: 0,
  activitiesDetected: 0,
  startTime: Date.now()
};

// Advanced threat patterns
const THREAT_PATTERNS = {
  cryptoMining: [
    /coinhive/i, /cryptonight/i, /monero/i, /webassembly.*mining/i, /wasm.*hash/i,
    /stratum\+tcp/i, /mining.*pool/i, /hashrate/i, /cpu.*miner/i, /javascript.*miner/i
  ],
  phishing: [
    /login.*verification/i, /account.*suspended/i, /verify.*account/i, /urgent.*action/i,
    /click.*here.*immediately/i, /suspended.*account/i, /security.*alert/i
  ],
  maliciousScripts: [
    /eval\(.*atob/i, /document\.write.*unescape/i, /fromCharCode.*join/i,
    /\.replace.*String\.fromCharCode/i, /obfuscated/i
  ]
};

// Malicious domains and IPs (sample threat intelligence)
const KNOWN_THREATS = [
  'malware-domain.com', 'phishing-site.net', 'crypto-miner.org',
  'fake-bank.com', 'suspicious-download.xyz', 'trojan-host.info'
];

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('Tab Guard Advanced extension installed');
  initializeStorage();
  initializeContextMenus();
  initializeThreatDatabase();
  setupPeriodicCleanup();
});

// Initialize storage structure
async function initializeStorage() {
  try {
    const result = await chrome.storage.local.get([
      'tabGuardLogs', 'tabGuardSettings', 'threatReports', 'quarantinedFiles', 'realTimeStats'
    ]);
    
    if (!result.tabGuardLogs) {
      await chrome.storage.local.set({ tabGuardLogs: [] });
    }
    
    if (!result.tabGuardSettings) {
      await chrome.storage.local.set({
        tabGuardSettings: {
          clipboardMonitoring: true,
          formMonitoring: true,
          cryptoMiningMonitoring: true,
          networkMonitoring: true,
          phishingProtection: true,
          realTimeScanning: true,
          autoQuarantine: true,
          notificationsEnabled: true,
          threatLevel: 'medium', // low, medium, high
          whitelistedDomains: [],
          blockedDomains: [],
          customRules: []
        }
      });
    }

    if (!result.threatReports) {
      await chrome.storage.local.set({ threatReports: [] });
    }

    if (!result.quarantinedFiles) {
      await chrome.storage.local.set({ quarantinedFiles: [] });
    }

    if (!result.realTimeStats) {
      await chrome.storage.local.set({ realTimeStats: realTimeStats });
    }
  } catch (error) {
    console.error('Error initializing storage:', error);
  }
}

// Initialize context menus
function initializeContextMenus() {
  chrome.contextMenus.create({
    id: 'scan-page',
    title: 'Scan this page for threats',
    contexts: ['page']
  });

  chrome.contextMenus.create({
    id: 'block-domain',
    title: 'Block this domain',
    contexts: ['page']
  });

  chrome.contextMenus.create({
    id: 'export-logs',
    title: 'Export security logs',
    contexts: ['action']
  });
}

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  switch (info.menuItemId) {
    case 'scan-page':
      await performDeepScan(tab.id);
      break;
    case 'block-domain':
      await blockDomain(extractDomain(tab.url));
      break;
    case 'export-logs':
      await exportSecurityLogs();
      break;
  }
});

// Initialize threat database
function initializeThreatDatabase() {
  KNOWN_THREATS.forEach(threat => threatDatabase.add(threat));
}

// Setup periodic cleanup
function setupPeriodicCleanup() {
  chrome.alarms.create('cleanup', { periodInMinutes: 60 });
  chrome.alarms.create('stats-update', { periodInMinutes: 5 });
}

// Handle alarms
chrome.alarms.onAlarm.addListener((alarm) => {
  switch (alarm.name) {
    case 'cleanup':
      performPeriodicCleanup();
      break;
    case 'stats-update':
      updateRealTimeStats();
      break;
  }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    initializeTabMonitoring(tabId, tab.url);
    checkUrlThreat(tab.url, tabId);
  }
});

// Listen for tab removal
chrome.tabs.onRemoved.addListener((tabId) => {
  cleanupTabMonitoring(tabId);
});

// Initialize monitoring for a specific tab
function initializeTabMonitoring(tabId, url) {
  const domain = extractDomain(url);
  
  tabMonitoringData[tabId] = {
    url: url,
    domain: domain,
    startTime: Date.now(),
    suspiciousActivities: [],
    networkRequests: [],
    riskScore: 0,
    threatLevel: 'low',
    cpuUsage: {
      requestAnimationFrameCalls: 0,
      setIntervalCalls: 0,
      webWorkerCreations: 0,
      lastCheck: Date.now()
    },
    permissions: {
      clipboard: false,
      camera: false,
      microphone: false,
      location: false,
      notifications: false
    },
    behaviorAnalysis: {
      redirectAttempts: 0,
      popupAttempts: 0,
      downloadAttempts: 0,
      formSubmissions: 0
    }
  };
  
  realTimeStats.tabsMonitored++;
  startCpuMonitoring(tabId);
  startNetworkMonitoring(tabId);
}

// Cleanup monitoring data when tab is closed
function cleanupTabMonitoring(tabId) {
  delete tabMonitoringData[tabId];
  delete networkMonitoringData[tabId];
  
  if (cpuMonitoringIntervals[tabId]) {
    clearInterval(cpuMonitoringIntervals[tabId]);
    delete cpuMonitoringIntervals[tabId];
  }
}

// Start CPU usage monitoring
function startCpuMonitoring(tabId) {
  if (cpuMonitoringIntervals[tabId]) {
    clearInterval(cpuMonitoringIntervals[tabId]);
  }
  
  cpuMonitoringIntervals[tabId] = setInterval(async () => {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tabId },
        func: checkCpuIntensiveOperations
      });
    } catch (error) {
      cleanupTabMonitoring(tabId);
    }
  }, 3000);
}

// Start network monitoring
function startNetworkMonitoring(tabId) {
  if (!networkMonitoringData[tabId]) {
    networkMonitoringData[tabId] = {
      requests: [],
      suspiciousRequests: [],
      totalRequests: 0
    };
  }
}

// Enhanced CPU monitoring function
function checkCpuIntensiveOperations() {
  if (window.tabGuardCpuMonitor) {
    const monitor = window.tabGuardCpuMonitor;
    const now = Date.now();
    const timeDiff = now - monitor.lastCheck;
    
    const rafRate = (monitor.rafCalls / timeDiff) * 1000;
    const intervalRate = (monitor.intervalCalls / timeDiff) * 1000;
    const workerRate = (monitor.workerCreations / timeDiff) * 1000;
    
    // Enhanced thresholds with dynamic adjustment
    const RAF_THRESHOLD = 40;
    const INTERVAL_THRESHOLD = 15;
    const WORKER_THRESHOLD = 2;
    
    let threatLevel = 'low';
    let riskScore = 0;
    
    if (rafRate > RAF_THRESHOLD) {
      riskScore += 30;
      threatLevel = 'medium';
    }
    if (intervalRate > INTERVAL_THRESHOLD) {
      riskScore += 25;
      threatLevel = 'medium';
    }
    if (workerRate > WORKER_THRESHOLD) {
      riskScore += 45;
      threatLevel = 'high';
    }
    
    if (riskScore > 50) {
      chrome.runtime.sendMessage({
        type: 'CRYPTO_MINING_DETECTED',
        data: {
          url: window.location.href,
          rafRate: rafRate,
          intervalRate: intervalRate,
          workerRate: workerRate,
          riskScore: riskScore,
          threatLevel: threatLevel,
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

// Check URL against threat database
async function checkUrlThreat(url, tabId) {
  const domain = extractDomain(url);
  
  if (threatDatabase.has(domain)) {
    await handleThreatDetected(tabId, {
      type: 'MALICIOUS_DOMAIN',
      data: {
        url: url,
        domain: domain,
        threatType: 'known_malicious',
        riskScore: 100
      }
    });
  }
  
  // Check against threat patterns
  for (const [category, patterns] of Object.entries(THREAT_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(url)) {
        await handleThreatDetected(tabId, {
          type: 'SUSPICIOUS_URL_PATTERN',
          data: {
            url: url,
            domain: domain,
            category: category,
            pattern: pattern.toString(),
            riskScore: 70
          }
        });
        break;
      }
    }
  }
}

// Handle threat detection
async function handleThreatDetected(tabId, threat) {
  realTimeStats.threatsBlocked++;
  
  // Update tab monitoring data
  if (tabMonitoringData[tabId]) {
    tabMonitoringData[tabId].riskScore += threat.data.riskScore || 50;
    tabMonitoringData[tabId].threatLevel = calculateThreatLevel(tabMonitoringData[tabId].riskScore);
  }
  
  // Store threat report
  const threatReport = {
    ...threat,
    tabId: tabId,
    timestamp: Date.now(),
    blocked: true
  };
  
  const result = await chrome.storage.local.get(['threatReports']);
  const reports = result.threatReports || [];
  reports.push(threatReport);
  
  if (reports.length > 500) {
    reports.splice(0, reports.length - 500);
  }
  
  await chrome.storage.local.set({ threatReports: reports });
  
  // Show notification for high-risk threats
  if (threat.data.riskScore > 70) {
    showThreatNotification(threat);
  }
  
  // Auto-block if enabled
  const settings = await chrome.storage.local.get(['tabGuardSettings']);
  if (settings.tabGuardSettings?.autoQuarantine && threat.data.riskScore > 80) {
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL('blocked.html') });
  }
}

// Calculate threat level based on risk score
function calculateThreatLevel(riskScore) {
  if (riskScore >= 80) return 'critical';
  if (riskScore >= 60) return 'high';
  if (riskScore >= 30) return 'medium';
  return 'low';
}

// Show threat notification
function showThreatNotification(threat) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.svg',
    title: 'Tab Guard Security Alert',
    message: `Threat detected: ${threat.type}\nDomain: ${threat.data.domain}`,
    priority: 2
  });
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener(async (message, sender, sendResponse) => {
  if (sender.tab) {
    await handleSuspiciousActivity(sender.tab.id, message);
  }
  
  // Handle API requests from popup
  if (message.action) {
    switch (message.action) {
      case 'GET_MONITORING_DATA':
        sendResponse({
          tabData: tabMonitoringData,
          networkData: networkMonitoringData,
          realTimeStats: realTimeStats,
          success: true
        });
        break;
        
      case 'GET_ACTIVITY_LOGS':
        const logs = await chrome.storage.local.get(['tabGuardLogs']);
        sendResponse({
          logs: logs.tabGuardLogs || [],
          success: true
        });
        return true;
        
      case 'GET_THREAT_REPORTS':
        const reports = await chrome.storage.local.get(['threatReports']);
        sendResponse({
          reports: reports.threatReports || [],
          success: true
        });
        return true;
        
      case 'EXPORT_LOGS':
        await exportSecurityLogs();
        sendResponse({ success: true });
        break;
        
      case 'DEEP_SCAN':
        await performDeepScan(message.tabId);
        sendResponse({ success: true });
        break;
    }
  }
});

// Enhanced suspicious activity handler
async function handleSuspiciousActivity(tabId, message) {
  const activity = {
    type: message.type,
    data: message.data,
    timestamp: Date.now(),
    tabId: tabId,
    severity: calculateSeverity(message.type),
    riskScore: calculateRiskScore(message.type, message.data)
  };
  
  realTimeStats.activitiesDetected++;
  
  // Store in tab monitoring data
  if (tabMonitoringData[tabId]) {
    tabMonitoringData[tabId].suspiciousActivities.push(activity);
    tabMonitoringData[tabId].riskScore += activity.riskScore;
    tabMonitoringData[tabId].threatLevel = calculateThreatLevel(tabMonitoringData[tabId].riskScore);
  }
  
  // Store in persistent storage
  try {
    const result = await chrome.storage.local.get(['tabGuardLogs']);
    const logs = result.tabGuardLogs || [];
    logs.push(activity);
    
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }
    
    await chrome.storage.local.set({ tabGuardLogs: logs });
    
    updateBadge(tabId);
    
    if (shouldShowNotification(message.type, activity.severity)) {
      showNotification(activity);
    }
  } catch (error) {
    console.error('Error storing activity log:', error);
  }
}

// Calculate severity based on activity type
function calculateSeverity(type) {
  const severityMap = {
    'CRYPTO_MINING_DETECTED': 'high',
    'AUTO_FORM_SUBMISSION': 'medium',
    'CLIPBOARD_ACCESS': 'low',
    'SUSPICIOUS_DOWNLOAD': 'high',
    'MALICIOUS_SCRIPT': 'critical',
    'PHISHING_ATTEMPT': 'critical',
    'PERMISSION_REQUEST': 'medium'
  };
  return severityMap[type] || 'low';
}

// Calculate risk score
function calculateRiskScore(type, data) {
  const baseScores = {
    'CRYPTO_MINING_DETECTED': 40,
    'AUTO_FORM_SUBMISSION': 25,
    'CLIPBOARD_ACCESS': 15,
    'SUSPICIOUS_DOWNLOAD': 50,
    'MALICIOUS_SCRIPT': 60,
    'PHISHING_ATTEMPT': 80,
    'PERMISSION_REQUEST': 20
  };
  
  let score = baseScores[type] || 10;
  
  // Adjust score based on data
  if (data.riskScore) {
    score = Math.max(score, data.riskScore);
  }
  
  return score;
}

// Enhanced badge update
function updateBadge(tabId) {
  if (tabMonitoringData[tabId]) {
    const threatLevel = tabMonitoringData[tabId].threatLevel;
    const activityCount = tabMonitoringData[tabId].suspiciousActivities.length;
    
    let color = '#28a745'; // green for safe
    let text = '';
    
    if (threatLevel === 'critical') {
      color = '#dc3545'; // red
      text = '!';
    } else if (threatLevel === 'high') {
      color = '#fd7e14'; // orange
      text = '!';
    } else if (threatLevel === 'medium') {
      color = '#ffc107'; // yellow
      text = activityCount > 0 ? activityCount.toString() : '';
    }
    
    chrome.action.setBadgeText({ text: text, tabId: tabId });
    chrome.action.setBadgeBackgroundColor({ color: color, tabId: tabId });
  }
}

// Enhanced notification check
function shouldShowNotification(activityType, severity) {
  const highRiskActivities = ['CRYPTO_MINING_DETECTED', 'AUTO_FORM_SUBMISSION', 'MALICIOUS_SCRIPT'];
  return highRiskActivities.includes(activityType) || severity === 'critical' || severity === 'high';
}

// Enhanced notification
function showNotification(activity) {
  const messages = {
    'CRYPTO_MINING_DETECTED': 'Cryptocurrency mining detected',
    'CLIPBOARD_ACCESS': 'Unauthorized clipboard access',
    'AUTO_FORM_SUBMISSION': 'Automatic form submission detected',
    'SUSPICIOUS_DOWNLOAD': 'Suspicious download blocked',
    'MALICIOUS_SCRIPT': 'Malicious script detected',
    'PHISHING_ATTEMPT': 'Phishing attempt blocked'
  };
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.svg',
    title: 'Tab Guard Security Alert',
    message: `${messages[activity.type] || 'Suspicious activity detected'}\nRisk: ${activity.severity}`,
    priority: activity.severity === 'critical' ? 2 : 1
  });
}

// Perform deep scan
async function performDeepScan(tabId) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: () => {
        // Comprehensive page scan
        const scanResults = {
          scripts: document.scripts.length,
          forms: document.forms.length,
          iframes: document.querySelectorAll('iframe').length,
          externalResources: document.querySelectorAll('script[src], link[href], img[src]').length,
          suspiciousElements: 0
        };
        
        // Check for suspicious patterns
        const pageContent = document.documentElement.innerHTML;
        const suspiciousPatterns = [
          /eval\(/gi, /document\.write/gi, /innerHTML.*script/gi,
          /onclick.*javascript/gi, /onload.*javascript/gi
        ];
        
        suspiciousPatterns.forEach(pattern => {
          const matches = pageContent.match(pattern);
          if (matches) {
            scanResults.suspiciousElements += matches.length;
          }
        });
        
        chrome.runtime.sendMessage({
          type: 'DEEP_SCAN_RESULT',
          data: scanResults
        });
      }
    });
  } catch (error) {
    console.error('Deep scan failed:', error);
  }
}

// Block domain
async function blockDomain(domain) {
  const result = await chrome.storage.local.get(['tabGuardSettings']);
  const settings = result.tabGuardSettings || {};
  
  if (!settings.blockedDomains) {
    settings.blockedDomains = [];
  }
  
  if (!settings.blockedDomains.includes(domain)) {
    settings.blockedDomains.push(domain);
    await chrome.storage.local.set({ tabGuardSettings: settings });
    threatDatabase.add(domain);
  }
}

// Export security logs
async function exportSecurityLogs() {
  try {
    const [logs, reports, stats] = await Promise.all([
      chrome.storage.local.get(['tabGuardLogs']),
      chrome.storage.local.get(['threatReports']),
      chrome.storage.local.get(['realTimeStats'])
    ]);
    
    const exportData = {
      exportDate: new Date().toISOString(),
      logs: logs.tabGuardLogs || [],
      threatReports: reports.threatReports || [],
      statistics: stats.realTimeStats || realTimeStats
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    await chrome.downloads.download({
      url: url,
      filename: `tab-guard-security-logs-${new Date().toISOString().split('T')[0]}.json`
    });
  } catch (error) {
    console.error('Export failed:', error);
  }
}

// Periodic cleanup
async function performPeriodicCleanup() {
  try {
    const result = await chrome.storage.local.get(['tabGuardLogs', 'threatReports']);
    const logs = result.tabGuardLogs || [];
    const reports = result.threatReports || [];
    
    // Keep only last 30 days of data
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
    
    const filteredLogs = logs.filter(log => log.timestamp > thirtyDaysAgo);
    const filteredReports = reports.filter(report => report.timestamp > thirtyDaysAgo);
    
    await chrome.storage.local.set({
      tabGuardLogs: filteredLogs,
      threatReports: filteredReports
    });
  } catch (error) {
    console.error('Cleanup failed:', error);
  }
}

// Update real-time stats
async function updateRealTimeStats() {
  realTimeStats.tabsMonitored = Object.keys(tabMonitoringData).length;
  await chrome.storage.local.set({ realTimeStats: realTimeStats });
}

// Utility function to extract domain from URL
function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (error) {
    return url;
  }
}