const nconf = require('nconf');
const axios = require('axios');
const winston = require('winston');
const fs = require('fs');
const CSV = require('comma-separated-values');

const logger = winston.createLogger({
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.colorize(),
                winston.format.simple()
            ),
            level: 'info',
            handleExceptions: true
        })
    ],
    exitOnError: false
});

nconf.argv()
  .env()
  .file({ file: './config.json' });

const domain = nconf.get('AUTH0_DOMAIN');
const clientId = nconf.get('AUTH0_CLIENT_ID');
const clientSecret = nconf.get('AUTH0_CLIENT_SECRET');

// Get access token for Management API
let accessToken = null;

const getAccessToken = async function() {
  if (accessToken) {
    return accessToken;
  }
  
  try {
    // OAuth token endpoint requires application/x-www-form-urlencoded
    const params = new URLSearchParams();
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('audience', `https://${domain}/api/v2/`);
    params.append('grant_type', 'client_credentials');
    
    const response = await axios.post(`https://${domain}/oauth/token`, params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    
    if (!response.data.access_token) {
      throw new Error('No access token in response. Check that your M2M app is authorized for Management API with read:logs scope.');
    }
    
    accessToken = response.data.access_token;
    logger.debug('Access token obtained successfully');
    return accessToken;
  } catch (err) {
    if (err.response && err.response.data) {
      const errorData = err.response.data;
      if (errorData.error === 'access_denied' || errorData.error === 'unauthorized_client') {
        logger.error('Authentication failed. Please verify:');
        logger.error('1. Your Machine to Machine application is authorized for the "Auth0 Management API"');
        logger.error('2. The application has the "read:logs" scope enabled');
        logger.error('3. Your client_id and client_secret are correct');
        logger.error(`Error: ${errorData.error_description || errorData.error}`);
      } else {
        logger.error('Error getting access token:', errorData);
      }
    } else {
      logger.error('Error getting access token:', err.message);
    }
    throw err;
  }
};

const logs = [];

const getLogTypes = function() {
  return {
    's': 'Success Login',
    'seacft': 'Success Exchange',
    'feacft': 'Failed Exchange',
    'f': 'Failed Login',
    'w': 'Warnings During Login',
    'du': 'Deleted User',
    'fu': 'Failed Login (invalid email/username)',
    'fp': 'Failed Login (wrong password)',
    'fc': 'Failed by Connector',
    'fco': 'Failed by CORS',
    'con': 'Connector Online',
    'coff': 'Connector Offline',
    'fcpro': 'Failed Connector Provisioning',
    'ss': 'Success Signup',
    'fs': 'Failed Signup',
    'cs': 'Code Sent',
    'cls': 'Code/Link Sent',
    'sv': 'Success Verification Email',
    'fv': 'Failed Verification Email',
    'scp': 'Success Change Password',
    'fcp': 'Failed Change Password',
    'sce': 'Success Change Email',
    'fce': 'Failed Change Email',
    'scu': 'Success Change Username',
    'fcu': 'Failed Change Username',
    'scpn': 'Success Change Phone Number',
    'fcpn': 'Failed Change Phone Number',
    'svr': 'Success Verification Email Request',
    'fvr': 'Failed Verification Email Request',
    'scpr': 'Success Change Password Request',
    'fcpr': 'Failed Change Password Request',
    'fn': 'Failed Sending Notification',
    'sapi': 'API Operation',
    'fapi': 'Failed API Operation',
    'limit_wc': 'Blocked Account',
    'limit_ui': 'Too Many Calls to /userinfo',
    'api_limit': 'Rate Limit On API',
    'sdu': 'Successful User Deletion',
    'fdu': 'Failed User Deletion'
  };
};

const formatLogRecord = function(record, logTypeMap) {
  // Extract username from user_name, user_id, or details
  let username = record.user_name || '';
  if (!username && record.user_id) {
    // Try to extract username from user_id (format: auth0|xxx or provider|id)
    username = record.user_id;
  }
  if (!username && record.details && record.details.username) {
    username = record.details.username;
  }

  // Format the event type
  const eventType = logTypeMap[record.type] || record.type || 'Unknown Event';

  // Format timestamp
  const timestamp = record.date ? new Date(record.date).toISOString() : '';

  // Clean description
  let description = '';
  if (record.description) {
    description = record.description.replace(/(\s+|\;)/g, ' ').trim();
  }

  // Clean details (if it's an object, stringify it)
  let details = '';
  if (record.details) {
    if (typeof record.details === 'object') {
      details = JSON.stringify(record.details).replace(/(\s+|\;)/g, ' ').trim();
    } else {
      details = String(record.details).replace(/(\s+|\;)/g, ' ').trim();
    }
  }

  // Build the formatted record with all useful fields
  return {
    timestamp: timestamp,
    date: record.date || '',
    type: eventType,
    type_code: record.type || '',
    username: username,
    user_id: record.user_id || '',
    user_name: record.user_name || '',
    description: description,
    ip: record.ip || '',
    user_agent: record.user_agent || '',
    client_id: record.client_id || '',
    client_name: record.client_name || '',
    connection: record.connection || '',
    connection_id: record.connection_id || '',
    details: details,
    log_id: record._id || record.log_id || '',
    location_info: record.location_info ? JSON.stringify(record.location_info) : '',
    is_mobile: record.is_mobile ? 'true' : 'false'
  };
};

const done = function() {
  logger.info(`All logs have been downloaded, total: ${logs.length}`);

  const logTypeMap = getLogTypes();
  const data = logs.map(function(record) {
    return formatLogRecord(record, logTypeMap);
  });

  const output = new CSV(data, { header: true, cellDelimiter: ',' }).encode();
  fs.writeFileSync('./auth0-logs.csv', output);
  logger.info('CSV file saved to auth0-logs.csv');
};

// Track checkpoints we've actually used (not logs that exist)
const usedCheckpoints = new Set();

// NEW APPROACH: Auth0's 'from' parameter returns logs NEWER than the checkpoint (ascending order)
// So we should start from the OLDEST date and paginate FORWARD through time
// This will get us all historical data
const getLogs = async function(checkPoint) {
  try {
    const token = await getAccessToken();
    
    const params = {
      take: 100,
      sort: 'date:1'  // Sort by date ascending (oldest first)
    };
    
    if (checkPoint) {
      // Use checkpoint to get logs AFTER this point (forward in time)
      params.from = checkPoint;
      logger.info(`Using checkpoint: ${checkPoint.substring(0, 30)}... (fetching newer logs)`);
    } else {
      // Start from the beginning - sort by date ascending will give us oldest logs first
      logger.info('Starting from oldest available logs in retention period (sorted by date ascending)');
    }

    const response = await axios.get(`https://${domain}/api/v2/logs`, {
      params: params,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    const result = response.data || [];

    if (result && result.length > 0) {
      // Add all logs without deduplication - Auth0 API shouldn't return duplicates
      result.forEach(function(log) {
        logs.push(log);
      });

      logger.info(`Processed ${logs.length} total logs (fetched ${result.length} in this batch).`);
      
      // On first batch, show retention info
      if (!checkPoint && result.length > 0 && result[0].date) {
        const firstDate = new Date(result[0].date);
        const daysAgo = (new Date() - firstDate) / (1000 * 60 * 60 * 24);
        logger.info(`OLDEST log available: ${firstDate.toISOString()} (${daysAgo.toFixed(1)} days ago)`);
        logger.info(`This indicates your Auth0 tenant's log retention period is approximately ${Math.ceil(daysAgo)} days.`);
        
        if (daysAgo < 30) {
          logger.warn(`⚠ WARNING: Log retention appears to be only ${Math.ceil(daysAgo)} days.`);
          logger.warn(`If you need longer retention, you may need to:`);
          logger.warn(`  1. Upgrade your Auth0 plan for longer retention`);
          logger.warn(`  2. Set up log streaming to export logs continuously`);
          logger.warn(`  3. Check Auth0 Dashboard → Monitoring → Logs for retention settings`);
        }
      }
      
      // Find the oldest log in the batch to use as next checkpoint
      const logsWithDates = result.filter(log => log.date);
      if (logsWithDates.length > 0) {
        logsWithDates.sort((a, b) => {
          return new Date(a.date) - new Date(b.date);
        });
        
        const oldestLogInBatch = logsWithDates[0];
        const newestLogInBatch = logsWithDates[logsWithDates.length - 1];
        
        const oldestDate = oldestLogInBatch.date ? new Date(oldestLogInBatch.date).toISOString() : 'unknown';
        const newestDate = newestLogInBatch.date ? new Date(newestLogInBatch.date).toISOString() : 'unknown';
        
        logger.info(`Batch: ${result.length} logs | Date range: ${oldestDate} (oldest) to ${newestDate} (newest)`);
        
        // Use the NEWEST log ID as the next checkpoint
        // Since 'from' returns logs AFTER the checkpoint, we want to continue forward from the newest
        const nextCheckpoint = newestLogInBatch._id;
        
        // Check if we're going forward in time (which is what we want now)
        if (checkPoint) {
          const previousLog = logs.find(log => log._id === checkPoint);
          if (previousLog && previousLog.date) {
            const prevDate = new Date(previousLog.date);
            const currentNewest = new Date(newestLogInBatch.date);
            if (currentNewest > prevDate) {
              const daysDiff = (currentNewest - prevDate) / (1000 * 60 * 60 * 24);
              logger.info(`✓ Going forward in time (${daysDiff.toFixed(1)} days forward from ${prevDate.toISOString()} to ${newestDate})`);
            } else {
              logger.warn(`⚠ Warning: Not progressing forward. Previous: ${prevDate.toISOString()}, Current: ${newestDate}`);
            }
          }
        }
        
        // Continue fetching if we got results and haven't reached the same checkpoint
        if (result.length > 0 && nextCheckpoint !== checkPoint) {
          // Check if we've USED this checkpoint before (avoid infinite loop)
          if (usedCheckpoints.has(nextCheckpoint)) {
            logger.info(`✓ Reached duplicate checkpoint. Total logs collected: ${logs.length}`);
            done();
            return;
          }
          
          // Mark checkpoints as used
          if (checkPoint) {
            usedCheckpoints.add(checkPoint);
          }
          usedCheckpoints.add(nextCheckpoint);
          
          // If we got fewer logs than requested, we might be approaching the end
          if (result.length < 100) {
            logger.info(`Note: Batch is smaller than requested (${result.length} < 100). Approaching current time...`);
          }
          
          logger.info(`→ Fetching more logs from checkpoint: ${nextCheckpoint.substring(0, 30)}... (newest date: ${newestDate})`);
          // Use a small delay to avoid rate limits
          setTimeout(function() {
            getLogs(nextCheckpoint);
          }, 100);
        } else {
          logger.info(`✓ Completed. Reached current time at ${newestDate}`);
          done();
        }
      } else {
        logger.warn('No logs with dates found in batch');
        // Even if no dates, try to continue if we have a checkpoint
        if (checkPoint && result.length > 0) {
          const nextCheckpoint = result[result.length - 1]._id;
          logger.info(`Trying to continue with last log ID as checkpoint...`);
          setTimeout(function() {
            getLogs(nextCheckpoint);
          }, 100);
        } else {
          done();
        }
      }
    } else {
      // Empty result - we've reached the current time (no more logs available)
      logger.info(`No more logs to fetch. Reached current time.`);
      logger.info(`Total logs collected: ${logs.length}`);
      done();
    }
  } catch (err) {
    logger.error('Error getting logs', err.response?.data || err.message);
    
    // Reset token on auth errors
    if (err.response?.status === 401) {
      accessToken = null;
      logger.info('Access token expired, refreshing...');
      setTimeout(() => {
        getLogs(checkPoint);
      }, 1000);
      return;
    }
    
    // Handle rate limiting
    if (err.response?.status === 429 || err.statusCode === 429) {
      logger.info('Rate limit hit, waiting 5 seconds...');
      setTimeout(() => {
        getLogs(checkPoint);
      }, 5000);
      return;
    }
    
    // Handle 400 errors (bad request) - might be load-shedding or invalid parameters
    if (err.response?.status === 400) {
      logger.warn('Received 400 error (Bad Request). This might be due to:');
      logger.warn('1. Load-shedding on Auth0 servers');
      logger.warn('2. Invalid parameters');
      logger.warn('3. Reached pagination limit');
      logger.info('Waiting 2 seconds and retrying...');
      setTimeout(() => {
        getLogs(checkPoint);
      }, 2000);
      return;
    }
    
    // For other errors, throw
    throw err;
  }
};

(async function() {
  logger.info('Starting export...');
  
  try {
    // Start without checkpoint to get most recent logs first
    await getLogs();
  } catch (err) {
    logger.error('Error during export:', err);
    process.exit(1);
  }
})();
