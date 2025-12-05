const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const UAParser = require('ua-parser-js');
const geoip = require('geoip-lite');
const basicAuth = require('express-basic-auth');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting for tracking endpoints
const trackingLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});

// Apply rate limiting to tracking endpoints
app.use('/track', trackingLimiter);

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/email-tracker', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB Cloud');
});

// MongoDB Schemas
const emailOpenSchema = new mongoose.Schema({
  trackingId: { type: String, required: true, index: true },
  emailId: String,
  campaignId: String,
  
  // IP & Network Information
  ipAddress: String,
  ipInfo: {
    country: String,
    region: String,
    city: String,
    ll: [Number], // [latitude, longitude]
    metro: Number,
    range: [Number],
    timezone: String
  },
  
  // User Agent Information
  userAgent: String,
  parsedUA: {
    browser: {
      name: String,
      version: String,
      major: String
    },
    engine: {
      name: String,
      version: String
    },
    os: {
      name: String,
      version: String
    },
    device: {
      vendor: String,
      model: String,
      type: String
    },
    cpu: {
      architecture: String
    }
  },
  
  // Headers Information
  headers: {
    host: String,
    connection: String,
    'sec-ch-ua': String,
    'sec-ch-ua-mobile': String,
    'sec-ch-ua-platform': String,
    'upgrade-insecure-requests': String,
    'user-agent': String,
    accept: String,
    'sec-fetch-site': String,
    'sec-fetch-mode': String,
    'sec-fetch-user': String,
    'sec-fetch-dest': String,
    'accept-encoding': String,
    'accept-language': String,
    'x-forwarded-for': String,
    'x-real-ip': String,
    'cf-connecting-ip': String,
    'cf-ray': String,
    'cf-ipcountry': String,
    'cf-visitor': String,
    'x-forwarded-proto': String,
    'x-forwarded-host': String,
    'x-forwarded-port': String
  },
  
  // Request Information
  requestMethod: String,
  requestPath: String,
  requestQuery: Object,
  requestProtocol: String,
  
  // Timing Information
  timestamp: { type: Date, default: Date.now },
  openedAt: String, // Human readable
  timezoneOffset: Number,
  
  // Additional Metadata
  isMobile: Boolean,
  isTablet: Boolean,
  isDesktop: Boolean,
  isBot: Boolean,
  referrer: String,
  
  // Tracking Metadata
  openCount: { type: Number, default: 1 },
  firstOpen: { type: Date, default: Date.now },
  lastOpen: { type: Date, default: Date.now },
  
  // Email Client Detection
  emailClient: String,
  imageLoading: String, // 'auto', 'manual', 'blocked'
  
  // Performance Metrics (if available)
  loadTime: Number,
  
  // Custom Fields
  metadata: Object
});

const EmailOpen = mongoose.model('EmailOpen', emailOpenSchema);

// Generate 1x1 transparent GIF
const transparentGIF = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');

// Helper: Extract IP address considering proxies
const getClientIp = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.headers['x-real-ip'] || 
         req.headers['cf-connecting-ip'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress || 
         req.ip;
};

// Helper: Parse user agent
const parseUserAgent = (uaString) => {
  const parser = new UAParser(uaString);
  return parser.getResult();
};

// Helper: Detect email client
const detectEmailClient = (headers, userAgent) => {
  const ua = userAgent.toLowerCase();
  
  if (ua.includes('gmail') || headers['user-agent']?.includes('Gmail')) return 'Gmail';
  if (ua.includes('outlook') || ua.includes('ms-office')) return 'Outlook';
  if (ua.includes('apple mail') || ua.includes('macos')) return 'Apple Mail';
  if (ua.includes('yahoo')) return 'Yahoo Mail';
  if (ua.includes('thunderbird')) return 'Thunderbird';
  if (ua.includes('samsung')) return 'Samsung Email';
  if (ua.includes('protonmail')) return 'ProtonMail';
  if (ua.includes('roundcube')) return 'Roundcube';
  if (ua.includes('zimbra')) return 'Zimbra';
  
  // Check for common email client headers
  if (headers['x-mailer']) return headers['x-mailer'];
  if (headers['user-agent']?.includes('Microsoft Outlook')) return 'Outlook';
  
  return 'Unknown';
};

// Helper: Check if request is from bot/crawler
const isBotRequest = (userAgent) => {
  const bots = [
    'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
    'yandexbot', 'sogou', 'exabot', 'facebot', 'ia_archiver',
    'facebookexternalhit', 'linkedinbot', 'twitterbot', 'slackbot'
  ];
  
  const ua = userAgent.toLowerCase();
  return bots.some(bot => ua.includes(bot));
};

// Main tracking endpoint
app.get('/track/:trackingId', async (req, res) => {
  try {
    const { trackingId } = req.params;
    const clientIp = getClientIp(req);
    const geo = geoip.lookup(clientIp);
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const parsedUA = parseUserAgent(userAgent);
    
    // Determine device type
    const isMobile = parsedUA.device.type === 'mobile';
    const isTablet = parsedUA.device.type === 'tablet';
    const isDesktop = !isMobile && !isTablet && parsedUA.device.type !== 'wearable';
    const isBot = isBotRequest(userAgent);
    
    // Detect email client
    const emailClient = detectEmailClient(req.headers, userAgent);
    
    // Check if this tracking ID already exists
    const existingRecord = await EmailOpen.findOne({ trackingId });
    
    const now = new Date();
    const timezoneOffset = now.getTimezoneOffset();
    
    if (existingRecord) {
      // Update existing record
      existingRecord.openCount += 1;
      existingRecord.lastOpen = now;
      existingRecord.ipAddress = clientIp;
      existingRecord.ipInfo = geo;
      existingRecord.userAgent = userAgent;
      existingRecord.parsedUA = parsedUA;
      existingRecord.headers = req.headers;
      existingRecord.isMobile = isMobile;
      existingRecord.isTablet = isTablet;
      existingRecord.isDesktop = isDesktop;
      existingRecord.isBot = isBot;
      existingRecord.emailClient = emailClient;
      existingRecord.timezoneOffset = timezoneOffset;
      
      await existingRecord.save();
    } else {
      // Create new record
      const emailOpen = new EmailOpen({
        trackingId,
        ipAddress: clientIp,
        ipInfo: geo,
        userAgent,
        parsedUA,
        headers: req.headers,
        requestMethod: req.method,
        requestPath: req.path,
        requestQuery: req.query,
        requestProtocol: req.protocol,
        timestamp: now,
        openedAt: now.toISOString(),
        timezoneOffset,
        isMobile,
        isTablet,
        isDesktop,
        isBot,
        referrer: req.headers.referer || 'Direct',
        emailClient,
        firstOpen: now,
        lastOpen: now,
        metadata: {
          queryParams: req.query,
          originalUrl: req.originalUrl
        }
      });
      
      await emailOpen.save();
    }
    
    console.log(`Tracked: ${trackingId} | IP: ${clientIp} | Client: ${emailClient} | Device: ${parsedUA.device.type || 'desktop'}`);
    
    // Return 1x1 transparent GIF
    res.set({
      'Content-Type': 'image/gif',
      'Content-Length': transparentGIF.length,
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Tracking-ID': trackingId,
      'X-Tracked-At': now.toISOString(),
      'Access-Control-Allow-Origin': '*'
    });
    
    res.send(transparentGIF);
    
  } catch (error) {
    console.error('Tracking error:', error);
    // Still return the pixel even if tracking fails
    res.set({
      'Content-Type': 'image/gif',
      'Content-Length': transparentGIF.length,
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
    });
    res.send(transparentGIF);
  }
});

// Dashboard API endpoints (protected with basic auth)
const dashboardAuth = basicAuth({
  users: { 
    admin:'americansmooth',
    viewer:'samba'
  },
  challenge: true,
  realm: 'Email Tracking Dashboard'
});

// Get all tracking data
app.get('/api/tracking', dashboardAuth, async (req, res) => {
  try {
    const { limit = 100, page = 1, trackingId } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    let query = {};
    if (trackingId) {
      query.trackingId = trackingId;
    }
    
    const opens = await EmailOpen.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit))
      .lean();
    
    const total = await EmailOpen.countDocuments(query);
    
    res.json({
      success: true,
      data: opens,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
    
  } catch (error) {
    console.error('API error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Get statistics
app.get('/api/stats', dashboardAuth, async (req, res) => {
  try {
    // Total opens
    const totalOpens = await EmailOpen.countDocuments();
    
    // Unique tracking IDs
    const uniqueEmails = await EmailOpen.distinct('trackingId');
    
    // Today's opens
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const opensToday = await EmailOpen.countDocuments({ timestamp: { $gte: today } });
    
    // Device breakdown
    const deviceStats = await EmailOpen.aggregate([
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$isMobile', true] },
              'Mobile',
              { $cond: [{ $eq: ['$isTablet', true] }, 'Tablet', 'Desktop'] }
            ]
          },
          count: { $sum: 1 }
        }
      }
    ]);
    
    // Browser breakdown
    const browserStats = await EmailOpen.aggregate([
      {
        $group: {
          _id: '$parsedUA.browser.name',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    // Email client breakdown
    const emailClientStats = await EmailOpen.aggregate([
      {
        $group: {
          _id: '$emailClient',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    // Geographic breakdown
    const geoStats = await EmailOpen.aggregate([
      {
        $group: {
          _id: '$ipInfo.country',
          count: { $sum: 1 }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);
    
    res.json({
      success: true,
      stats: {
        totalOpens,
        uniqueEmails: uniqueEmails.length,
        opensToday,
        deviceStats,
        browserStats,
        emailClientStats,
        geoStats,
      }
    });
    
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Get specific tracking ID details
app.get('/api/tracking/:trackingId', dashboardAuth, async (req, res) => {
  try {
    const { trackingId } = req.params;
    
    const opens = await EmailOpen.find({ trackingId }).sort({ timestamp: -1 }).lean();
    
    // Calculate open times
    const openTimes = opens.map(open => ({
      timestamp: open.timestamp,
      ip: open.ipAddress,
      client: open.emailClient,
      device: open.isMobile ? 'Mobile' : (open.isTablet ? 'Tablet' : 'Desktop')
    }));
    
    res.json({
      success: true,
      trackingId,
      opens: {
        total: opens.length,
        firstOpen: opens.length > 0 ? opens[opens.length - 1].timestamp : null,
        lastOpen: opens.length > 0 ? opens[0].timestamp : null,
        details: openTimes
      },
      recentOpens: opens.slice(0, 10),
    });
    
  } catch (error) {
    console.error('Details error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Email Tracking Pixel API',
    version: '1.0.0',
    endpoints: {
      tracking: 'GET /track/:trackingId',
      api: {
        trackingData: 'GET /api/tracking (basic auth required)',
        statistics: 'GET /api/stats (basic auth required)',
        generate: 'GET /api/generate/:trackingId (basic auth required)'
      },
      health: 'GET /health'
    },
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Email Tracking Server running on port ${PORT}`);
});