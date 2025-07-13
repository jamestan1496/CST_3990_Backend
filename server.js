const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const QRCode = require('qrcode');
const { Server } = require('socket.io');
const http = require('http');
const axios = require('axios');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Enhanced static file serving with better error handling
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    // Add proper headers for images
    setHeaders: (res, path, stat) => {
        res.set({
            'Cache-Control': 'public, max-age=86400', // Cache for 1 day
            'Cross-Origin-Resource-Policy': 'cross-origin'
        });
    },
    // Handle missing files gracefully
    fallthrough: false
}));
app.use('/uploads', (req, res, next) => {
    res.status(404).json({ 
        error: 'Image not found',
        path: req.path,
        suggestion: 'The image may have been deleted or the filename is incorrect'
    });
});

// Configuration
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jamestan1496:eventhive@cluster0.gf6vat2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const CLUSTERING_SERVICE_URL = process.env.CLUSTERING_SERVICE_URL || 'https://cst-3990-pythonclustering.onrender.com';

// Create uploads directory if it doesn't exist (add this after your middleware setup)
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('Created uploads directory:', uploadsDir);
}
// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadsPath = path.join(__dirname, 'uploads');
        // Ensure directory exists
        if (!fs.existsSync(uploadsPath)) {
            fs.mkdirSync(uploadsPath, { recursive: true });
        }
        cb(null, uploadsPath);
    },
    filename: function (req, file, cb) {
        // Create unique filename with original extension
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const extension = path.extname(file.originalname);
        const filename = uniqueSuffix + extension;
        
        console.log('Storing file as:', filename);
        cb(null, filename);
    }
});
const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        // Check file type
        const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'));
        }
    }
});

// MongoDB connection
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['organizer', 'attendee'], default: 'attendee' },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  interests: [String],
  professionalRole: String,
  createdAt: { type: Date, default: Date.now }
});

const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  location: { type: String, required: true },
  organizer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  image: String,
  maxAttendees: { type: Number, default: 100 },
  status: { type: String, enum: ['upcoming', 'live', 'completed'], default: 'upcoming' },
  sessions: [{
    title: String,
    speaker: String,
    speakerBio: String,
    startTime: String,
    endTime: String,
    description: String
  }],
  createdAt: { type: Date, default: Date.now }
});

const registrationSchema = new mongoose.Schema({
  event: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
  attendee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  qrCode: String,
  checkedIn: { type: Boolean, default: false },
  checkInTime: Date,
  cluster: String,
  registrationDate: { type: Date, default: Date.now }
});

const sessionTrackingSchema = new mongoose.Schema({
  event: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
  attendee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  session: String,
  joinTime: { type: Date, default: Date.now },
  leaveTime: Date,
  duration: Number
});

// Models
const User = mongoose.model('User', userSchema);
const Event = mongoose.model('Event', eventSchema);
const Registration = mongoose.model('Registration', registrationSchema);
const SessionTracking = mongoose.model('SessionTracking', sessionTrackingSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Role-based authorization middleware
const authorizeRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Utility functions
const generateQRCode = async (data) => {
  try {
    const qrCodeData = await QRCode.toDataURL(JSON.stringify(data));
    return qrCodeData;
  } catch (error) {
    throw new Error('QR code generation failed');
  }
};

const calculateClusteringMetrics = (clusters) => {
  // Simple clustering metrics calculation
  const totalPoints = clusters.reduce((sum, cluster) => sum + cluster.length, 0);
  const numClusters = clusters.length;
  const avgClusterSize = totalPoints / numClusters;
  
  return {
    totalPoints,
    numClusters,
    avgClusterSize,
    silhouetteScore: Math.random() * 0.5 + 0.5 // Mock silhouette score
  };
};

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join_event', (eventId) => {
    socket.join(eventId);
    console.log(`User ${socket.id} joined event ${eventId}`);
  });

  socket.on('leave_event', (eventId) => {
    socket.leave(eventId);
    console.log(`User ${socket.id} left event ${eventId}`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// API Routes

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, role, interests, professionalRole } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword,
      firstName,
      lastName,
      role: role || 'attendee',
      interests: interests || [],
      professionalRole
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Event routes
// Replace your existing event creation route with this:
// Get all events (for attendees to browse and register)
app.get('/api/events', async (req, res) => {
  try {
    const { search, status, limit = 50, page = 1 } = req.query;
    
    // Build filter object
    const filter = {};
    
    // Add search filter
    if (search && search.trim()) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Add status filter
    if (status) {
      filter.status = status;
    }
    
    // Calculate pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Get events with organizer info
    const events = await Event.find(filter)
      .populate('organizer', 'firstName lastName email')
      .sort({ date: 1 }) // Sort by date ascending
      .skip(skip)
      .limit(parseInt(limit));
    
    // Get total count for pagination
    const total = await Event.countDocuments(filter);
    
    // Add attendee count to each event
    const eventsWithCounts = await Promise.all(
      events.map(async (event) => {
        const attendeeCount = await Registration.countDocuments({ event: event._id });
        const eventObj = event.toObject();
        return {
          ...eventObj,
          attendeeCount,
          spotsRemaining: event.maxAttendees - attendeeCount
        };
      })
    );
    
    res.json({
      events: eventsWithCounts,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});
app.post('/api/events', authenticateToken, authorizeRole(['organizer']), upload.single('image'), async (req, res) => {
  try {
    const { title, description, date, time, location, maxAttendees, sessions } = req.body;

    console.log('Creating event with date:', date, 'time:', time); // Debug log

    // Validate that the event date is not in the past
    const eventDate = new Date(date);
    const currentDate = new Date();
    
    console.log('Event date:', eventDate); // Debug log
    console.log('Current date:', currentDate); // Debug log
    
    // Set current date to start of day for comparison
    currentDate.setHours(0, 0, 0, 0);
    eventDate.setHours(0, 0, 0, 0);
    
    if (eventDate < currentDate) {
      console.log('Date validation failed: Event date is in the past'); // Debug log
      return res.status(400).json({ 
        error: 'Cannot create event for a past date. Please select a current or future date.' 
      });
    }

    // Additional validation for time if event is today
    if (eventDate.getTime() === currentDate.getTime() && time) {
      const currentTime = new Date();
      const [hours, minutes] = time.split(':');
      const eventDateTime = new Date();
      eventDateTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);
      
      console.log('Time validation - Event time:', eventDateTime, 'Current time:', currentTime); // Debug log
      
      if (eventDateTime < currentTime) {
        console.log('Time validation failed: Event time is in the past'); // Debug log
        return res.status(400).json({ 
          error: 'Cannot create event for a past time today. Please select a future time.' 
        });
      }
    }

    console.log('Date validation passed, creating event...'); // Debug log

    const event = new Event({
      title,
      description,
      date: new Date(date),
      time,
      location,
      organizer: req.user.userId,
      maxAttendees: maxAttendees || 100,
      image: req.file ? req.file.filename : null,
      sessions: sessions ? JSON.parse(sessions) : []
    });

    await event.save();
    await event.populate('organizer', 'firstName lastName email');

    console.log('Event created successfully:', event._id); // Debug log

    res.status(201).json({
      message: 'Event created successfully',
      event
    });
  } catch (error) {
    console.error('Create event error:', error);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

// Also replace your event update route:
app.put('/api/events/:id', authenticateToken, authorizeRole(['organizer']), upload.single('image'), async (req, res) => {
  try {
    const { title, description, date, time, location, maxAttendees, sessions, status } = req.body;

    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    if (event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to update this event' });
    }

    // Validate date if it's being updated
    if (date) {
      const eventDate = new Date(date);
      const currentDate = new Date();
      
      // Set current date to start of day for comparison
      currentDate.setHours(0, 0, 0, 0);
      eventDate.setHours(0, 0, 0, 0);
      
      if (eventDate < currentDate) {
        return res.status(400).json({ 
          error: 'Cannot update event to a past date. Please select a current or future date.' 
        });
      }

      // Additional validation for time if event is today and time is being updated
      if (eventDate.getTime() === currentDate.getTime() && time) {
        const currentTime = new Date();
        const [hours, minutes] = time.split(':');
        const eventDateTime = new Date();
        eventDateTime.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        
        if (eventDateTime < currentTime) {
          return res.status(400).json({ 
            error: 'Cannot update event to a past time today. Please select a future time.' 
          });
        }
      }
    }

    const updateData = {
      title: title || event.title,
      description: description || event.description,
      date: date ? new Date(date) : event.date,
      time: time || event.time,
      location: location || event.location,
      maxAttendees: maxAttendees || event.maxAttendees,
      status: status || event.status
    };

    if (req.file) {
      updateData.image = req.file.filename;
    }

    if (sessions) {
      updateData.sessions = JSON.parse(sessions);
    }

    const updatedEvent = await Event.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).populate('organizer', 'firstName lastName email');

    res.json({
      message: 'Event updated successfully',
      event: updatedEvent
    });
  } catch (error) {
    console.error('Update event error:', error);
    res.status(500).json({ error: 'Failed to update event' });
  }
});

app.post('/api/events', authenticateToken, authorizeRole(['organizer']), upload.single('image'), async (req, res) => {
  try {
    const { title, description, date, time, location, maxAttendees, sessions } = req.body;

    const event = new Event({
      title,
      description,
      date: new Date(date),
      time,
      location,
      organizer: req.user.userId,
      maxAttendees: maxAttendees || 100,
      image: req.file ? req.file.filename : null,
      sessions: sessions ? JSON.parse(sessions) : []
    });

    await event.save();
    await event.populate('organizer', 'firstName lastName email');

    res.status(201).json({
      message: 'Event created successfully',
      event
    });
  } catch (error) {
    console.error('Create event error:', error);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

app.put('/api/events/:id', authenticateToken, authorizeRole(['organizer']), upload.single('image'), async (req, res) => {
  try {
    const { title, description, date, time, location, maxAttendees, sessions, status } = req.body;

    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    if (event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to update this event' });
    }

    const updateData = {
      title: title || event.title,
      description: description || event.description,
      date: date ? new Date(date) : event.date,
      time: time || event.time,
      location: location || event.location,
      maxAttendees: maxAttendees || event.maxAttendees,
      status: status || event.status
    };

    if (req.file) {
      updateData.image = req.file.filename;
    }

    if (sessions) {
      updateData.sessions = JSON.parse(sessions);
    }

    const updatedEvent = await Event.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).populate('organizer', 'firstName lastName email');

    res.json({
      message: 'Event updated successfully',
      event: updatedEvent
    });
  } catch (error) {
    console.error('Update event error:', error);
    res.status(500).json({ error: 'Failed to update event' });
  }
});

app.delete('/api/events/:id', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    if (event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to delete this event' });
    }

    await Event.findByIdAndDelete(req.params.id);
    await Registration.deleteMany({ event: req.params.id });
    await SessionTracking.deleteMany({ event: req.params.id });

    res.json({ message: 'Event deleted successfully' });
  } catch (error) {
    console.error('Delete event error:', error);
    res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Registration routes
app.post('/api/events/:eventId/register', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const userId = req.user.userId;

    // Check if event exists
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    // Check if user is already registered
    const existingRegistration = await Registration.findOne({
      event: eventId,
      attendee: userId
    });

    if (existingRegistration) {
      return res.status(400).json({ 
        error: 'Already registered for this event',
        registrationId: existingRegistration._id
      });
    }

    // Check if event is full
    const registrationCount = await Registration.countDocuments({ event: eventId });
    if (registrationCount >= event.maxAttendees) {
      return res.status(400).json({ 
        error: 'Event is full',
        maxAttendees: event.maxAttendees,
        currentRegistrations: registrationCount
      });
    }

    // Generate QR code data
    const qrData = {
      eventId,
      userId,
      registrationId: new mongoose.Types.ObjectId().toString(),
      timestamp: new Date().toISOString()
    };

    let qrCode;
    try {
      qrCode = await generateQRCode(qrData);
    } catch (qrError) {
      console.error('QR code generation failed:', qrError);
      // Continue without QR code - it can be generated later
      qrCode = null;
    }

    // Create registration
    const registration = new Registration({
      event: eventId,
      attendee: userId,
      qrCode
    });

    await registration.save();

    console.log(`Registration successful: User ${userId} for event ${event.title}`);

    res.status(201).json({
      message: 'Registration successful',
      registration: {
        id: registration._id,
        eventId,
        qrCode,
        registrationDate: registration.registrationDate
      },
      event: {
        title: event.title,
        date: event.date,
        location: event.location
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Registration failed',
      details: error.message 
    });
  }
});

app.get('/api/events/:eventId/registrations', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Check if user is organizer of the event
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    if (event.organizer.toString() !== req.user.userId && req.user.role !== 'organizer') {
      return res.status(403).json({ error: 'Not authorized to view registrations' });
    }

    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole')
      .sort({ registrationDate: -1 });

    // Add safety checks for populated data
    const safeRegistrations = registrations.map(reg => ({
      _id: reg._id,
      event: reg.event,
      attendee: reg.attendee ? {
        _id: reg.attendee._id,
        firstName: reg.attendee.firstName || 'Unknown',
        lastName: reg.attendee.lastName || 'User',
        email: reg.attendee.email || 'No email',
        interests: reg.attendee.interests || [],
        professionalRole: reg.attendee.professionalRole || 'Not specified'
      } : {
        _id: 'unknown',
        firstName: 'Deleted',
        lastName: 'User',
        email: 'No email',
        interests: [],
        professionalRole: 'Not specified'
      },
      qrCode: reg.qrCode,
      checkedIn: reg.checkedIn,
      checkInTime: reg.checkInTime,
      cluster: reg.cluster,
      registrationDate: reg.registrationDate
    }));

    console.log(`Retrieved ${safeRegistrations.length} registrations for event ${event.title}`);

    res.json(safeRegistrations);
  } catch (error) {
    console.error('Get registrations error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch registrations',
      details: error.message 
    });
  }
});

// Check-in routes
app.post('/api/checkin', authenticateToken, async (req, res) => {
  try {
    const { qrData } = req.body;

    if (!qrData) {
      return res.status(400).json({ error: 'QR data required' });
    }

    let parsedData;
    try {
      parsedData = JSON.parse(qrData);
    } catch (parseError) {
      console.error('QR data parse error:', parseError);
      return res.status(400).json({ error: 'Invalid QR data format - must be valid JSON' });
    }

    const { eventId, userId } = parsedData;

    if (!eventId || !userId) {
      return res.status(400).json({ error: 'QR data missing required fields (eventId, userId)' });
    }

    // Find registration
    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    }).populate('attendee', 'firstName lastName email').populate('event', 'title');

    if (!registration) {
      return res.status(404).json({ 
        error: 'Registration not found',
        details: 'User is not registered for this event or invalid QR code'
      });
    }

    if (registration.checkedIn) {
      return res.status(400).json({ 
        error: 'Already checked in',
        checkInTime: registration.checkInTime
      });
    }

    // Update check-in status
    registration.checkedIn = true;
    registration.checkInTime = new Date();
    await registration.save();

    // Emit real-time update
    io.to(eventId).emit('checkin_update', {
      attendeeId: userId,
      attendeeName: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
      checkInTime: registration.checkInTime,
      eventTitle: registration.event.title
    });

    console.log(`Check-in successful: ${registration.attendee.firstName} ${registration.attendee.lastName} for ${registration.event.title}`);

    res.json({
      message: 'Check-in successful',
      attendee: {
        name: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
        email: registration.attendee.email,
        checkInTime: registration.checkInTime
      },
      event: {
        title: registration.event.title
      }
    });
  } catch (error) {
    console.error('Check-in error:', error);
    res.status(500).json({ 
      error: 'Check-in failed',
      details: error.message 
    });
  }
});
app.post('/api/events/:eventId/checkin-manual', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const { attendeeId } = req.body;
    const eventId = req.params.eventId;

    if (!attendeeId) {
      return res.status(400).json({ error: 'Attendee ID required' });
    }

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized to check in attendees for this event' });
    }

    // Find and update registration
    const registration = await Registration.findOne({
      event: eventId,
      attendee: attendeeId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found for this attendee and event' });
    }

    if (registration.checkedIn) {
      return res.status(400).json({ 
        error: 'Attendee already checked in',
        checkInTime: registration.checkInTime
      });
    }

    registration.checkedIn = true;
    registration.checkInTime = new Date();
    await registration.save();

    // Emit real-time update
    io.to(eventId).emit('checkin_update', {
      attendeeId,
      attendeeName: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
      checkInTime: registration.checkInTime,
      type: 'manual'
    });

    console.log(`Manual check-in successful: ${registration.attendee.firstName} ${registration.attendee.lastName}`);

    res.json({
      message: 'Manual check-in successful',
      attendee: {
        name: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
        email: registration.attendee.email,
        checkInTime: registration.checkInTime
      }
    });
  } catch (error) {
    console.error('Manual check-in error:', error);
    res.status(500).json({ 
      error: 'Manual check-in failed',
      details: error.message 
    });
  }
});
// Clustering routes
app.post('/api/events/:eventId/cluster', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const { algorithm = 'kmeans', numClusters = 3, eps = 0.5, minSamples = 2 } = req.body;

    console.log(`Starting clustering for event ${eventId} with algorithm: ${algorithm}`);

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Get registrations with attendee data
    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole');

    if (registrations.length === 0) {
      return res.status(400).json({ error: 'No registrations found for clustering' });
    }

    if (registrations.length < 2) {
      return res.status(400).json({ error: 'Need at least 2 attendees for clustering' });
    }

    // Prepare data for clustering service
    const attendeeData = registrations.map(reg => {
      if (!reg.attendee) {
        console.warn(`Registration ${reg._id} has missing attendee data`);
        return null;
      }
      
      return {
        id: reg.attendee._id.toString(),
        name: `${reg.attendee.firstName || 'Unknown'} ${reg.attendee.lastName || 'User'}`,
        email: reg.attendee.email || '',
        interests: reg.attendee.interests || [],
        professionalRole: reg.attendee.professionalRole || 'unknown'
      };
    }).filter(Boolean); // Remove null entries

    if (attendeeData.length < 2) {
      return res.status(400).json({ error: 'Insufficient valid attendee data for clustering' });
    }

    console.log(`Prepared ${attendeeData.length} attendees for clustering`);

    try {
      // Call the clustering microservice
      const clusteringPayload = {
        data: attendeeData,
        algorithm: algorithm,
        numClusters: numClusters,
        eps: eps,
        minSamples: minSamples
      };

      console.log(`Calling clustering service at ${CLUSTERING_SERVICE_URL}/cluster`);
      
      const clusteringResponse = await axios.post(`${CLUSTERING_SERVICE_URL}/cluster`, clusteringPayload, {
        timeout: 30000, // 30 second timeout
        headers: {
          'Content-Type': 'application/json'
        }
      });

      const { clusters, cluster_info, metrics } = clusteringResponse.data;
      
      console.log(`Clustering service returned ${clusters.length} clusters`);

      // Update registrations with cluster assignments
      for (let i = 0; i < clusters.length; i++) {
        const cluster = clusters[i];
        for (const attendeeId of cluster) {
          try {
            await Registration.findOneAndUpdate(
              { event: eventId, attendee: attendeeId },
              { cluster: `ai_cluster_${i}` }
            );
          } catch (updateError) {
            console.warn(`Failed to update cluster for attendee ${attendeeId}:`, updateError);
          }
        }
      }

      // Store clustering results in database for future reference
      try {
        await Event.findByIdAndUpdate(eventId, {
          $set: {
            clusteringResults: {
              algorithm: algorithm,
              metrics: metrics,
              clusterInfo: cluster_info,
              timestamp: new Date(),
              totalClusters: clusters.length
            }
          }
        });
      } catch (storeError) {
        console.warn('Failed to store clustering results:', storeError);
      }

      // Emit real-time update to connected clients
      io.to(eventId).emit('clustering_complete', {
        eventId: eventId,
        clustersCount: clusters.length,
        algorithm: algorithm,
        metrics: metrics
      });

      res.json({
        message: 'AI clustering completed successfully',
        clusters,
        cluster_info,
        metrics: {
          ...metrics,
          service_used: 'AI Clustering Service',
          algorithm_details: {
            name: algorithm,
            parameters: algorithm === 'kmeans' ? { numClusters } : { eps, minSamples }
          }
        },
        totalAttendees: attendeeData.length
      });

    } catch (clusteringError) {
      console.error('Clustering service error:', clusteringError.message);
      
      // Check if it's a timeout or connection error
      if (clusteringError.code === 'ECONNREFUSED' || clusteringError.code === 'ETIMEDOUT') {
        console.log('Clustering service unavailable, falling back to simple clustering');
        
        // Fallback to enhanced simple clustering
        const fallbackResult = await performFallbackClustering(attendeeData, numClusters, eventId);
        
        res.json({
          message: 'Clustering completed using fallback method (AI service unavailable)',
          ...fallbackResult,
          service_used: 'Fallback Clustering',
          note: 'AI clustering service was unavailable. Consider starting the clustering service for better results.'
        });
      } else {
        throw clusteringError; // Re-throw if it's not a connection issue
      }
    }

  } catch (error) {
    console.error('Clustering error:', error);
    res.status(500).json({ 
      error: 'Clustering failed', 
      details: error.message,
      suggestion: 'Ensure the clustering service is running or try with fewer clusters'
    });
  }
});
app.get('/api/events/:eventId/clusters', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Verify user has access (organizer of event or admin)
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    if (event.organizer.toString() !== req.user.userId && req.user.role !== 'organizer') {
      return res.status(403).json({ error: 'Not authorized to view clusters' });
    }

    // Get registrations with cluster data
    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole')
      .sort({ cluster: 1 });

    // Group by cluster with safety checks
    const clusterMap = new Map();
    registrations.forEach(reg => {
      if (!reg.attendee) {
        console.warn(`Registration ${reg._id} has no attendee data`);
        return;
      }

      const cluster = reg.cluster || 'unassigned';
      if (!clusterMap.has(cluster)) {
        clusterMap.set(cluster, []);
      }
      clusterMap.get(cluster).push({
        id: reg.attendee._id,
        name: `${reg.attendee.firstName || 'Unknown'} ${reg.attendee.lastName || 'User'}`,
        email: reg.attendee.email || 'No email',
        interests: reg.attendee.interests || [],
        professionalRole: reg.attendee.professionalRole || 'Not specified',
        checkedIn: reg.checkedIn
      });
    });

    const clusters = Array.from(clusterMap.entries()).map(([name, members]) => ({
      name,
      members,
      size: members.length
    }));

    console.log(`Retrieved ${clusters.length} clusters for event ${event.title}`);

    res.json(clusters);
  } catch (error) {
    console.error('Get clusters error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch clusters',
      details: error.message 
    });
  }
});

app.get('/api/clustering/algorithms', authenticateToken, async (req, res) => {
  try {
    const response = await axios.get(`${CLUSTERING_SERVICE_URL}/algorithms`, {
      timeout: 5000
    });
    
    res.json(response.data);
  } catch (error) {
    // Return default algorithms if service is unavailable
    res.json({
      algorithms: [
        {
          name: 'kmeans',
          display_name: 'K-Means',
          description: 'Partitions data into k clusters (AI service required)',
          parameters: [
            { name: 'numClusters', type: 'integer', default: 3, min: 2, max: 8 }
          ],
          available: false
        },
        {
          name: 'fallback',
          display_name: 'Role-Based Grouping',
          description: 'Groups attendees by professional roles (always available)',
          parameters: [
            { name: 'numClusters', type: 'integer', default: 3, min: 2, max: 6 }
          ],
          available: true
        }
      ],
      note: 'AI clustering service unavailable. Only fallback clustering is available.'
    });
  }
});

app.post('/api/events/:eventId/clusters/analyze', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;
    
    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Get clustered registrations
    const registrations = await Registration.find({ 
      event: eventId,
      cluster: { $exists: true, $ne: null }
    }).populate('attendee', 'firstName lastName email interests professionalRole');

    if (registrations.length === 0) {
      return res.status(400).json({ error: 'No clustered data found. Run clustering first.' });
    }

    // Prepare data for analysis
    const attendeeData = registrations.map(reg => ({
      id: reg.attendee._id.toString(),
      name: `${reg.attendee.firstName} ${reg.attendee.lastName}`,
      email: reg.attendee.email,
      interests: reg.attendee.interests || [],
      professionalRole: reg.attendee.professionalRole || 'unknown',
      cluster: reg.cluster
    }));

    // Group by clusters
    const clusterGroups = {};
    attendeeData.forEach(attendee => {
      if (!clusterGroups[attendee.cluster]) {
        clusterGroups[attendee.cluster] = [];
      }
      clusterGroups[attendee.cluster].push(attendee);
    });

    const clusters = Object.values(clusterGroups);

    try {
      // Try to use AI service for analysis
      const analysisResponse = await axios.post(`${CLUSTERING_SERVICE_URL}/cluster/analyze`, {
        clusters: clusters.map(cluster => cluster.map(a => a.id)),
        attendeeData: attendeeData
      }, { timeout: 10000 });

      res.json({
        ...analysisResponse.data,
        source: 'AI Analysis Service'
      });

    } catch (serviceError) {
      console.log('AI analysis service unavailable, using local analysis');
      
      // Fallback to local analysis
      const localAnalysis = performLocalClusterAnalysis(clusters);
      res.json({
        ...localAnalysis,
        source: 'Local Analysis (AI service unavailable)'
      });
    }

  } catch (error) {
    console.error('Cluster analysis error:', error);
    res.status(500).json({ error: 'Analysis failed', details: error.message });
  }
});

// Analytics routes
app.get('/api/events/:eventId/analytics', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Verify organizer owns the event
    const event = await Event.findById(eventId).populate('organizer', 'firstName lastName');
    if (!event || event.organizer._id.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    console.log(`Generating analytics for event: ${event.title}`);

    // Get analytics data
    const totalRegistrations = await Registration.countDocuments({ event: eventId });
    const totalCheckedIn = await Registration.countDocuments({ event: eventId, checkedIn: true });
    const clusterData = await Registration.distinct('cluster', { event: eventId });

    // Get session tracking data
    const sessionData = await SessionTracking.find({ event: eventId })
      .populate('attendee', 'firstName lastName');

    // Calculate session analytics if sessions exist
    let sessionAnalytics = [];
    if (event.sessions && event.sessions.length > 0) {
      sessionAnalytics = event.sessions.map(session => {
        const sessionTracking = sessionData.filter(s => s.session === session.title);
        return {
          title: session.title,
          speaker: session.speaker || 'TBD',
          startTime: session.startTime,
          endTime: session.endTime,
          totalJoins: sessionTracking.length,
          avgDuration: sessionTracking.reduce((sum, s) => sum + (s.duration || 0), 0) / sessionTracking.length || 0,
          engagementRate: Math.round((sessionTracking.length / Math.max(totalCheckedIn, 1)) * 100)
        };
      });
    }

    // Generate insights based on data
    const insights = [];
    
    if (totalRegistrations > 0) {
      const checkInRate = (totalCheckedIn / totalRegistrations * 100).toFixed(1);
      insights.push(`Check-in rate: ${checkInRate}%`);
      
      if (checkInRate < 70) {
        insights.push('Consider sending reminder emails to improve check-in rates');
      }
    }

    if (sessionAnalytics.length > 0) {
      const avgEngagement = sessionAnalytics.reduce((sum, s) => sum + s.engagementRate, 0) / sessionAnalytics.length;
      insights.push(`Average session engagement: ${avgEngagement.toFixed(1)}%`);
      
      const mostPopular = sessionAnalytics.reduce((prev, current) => 
        (prev.totalJoins > current.totalJoins) ? prev : current
      );
      insights.push(`Most popular session: "${mostPopular.title}" with ${mostPopular.totalJoins} joins`);
    }

    const clusterCount = clusterData.filter(c => c && c !== 'unassigned').length;
    if (clusterCount > 0) {
      insights.push(`Attendees organized into ${clusterCount} networking clusters`);
    }

    const analytics = {
      eventInfo: {
        title: event.title,
        date: event.date,
        organizer: `${event.organizer.firstName} ${event.organizer.lastName}`,
        maxAttendees: event.maxAttendees
      },
      attendance: {
        totalRegistrations,
        totalCheckedIn,
        checkInRate: totalRegistrations > 0 ? (totalCheckedIn / totalRegistrations * 100).toFixed(2) : 0,
        noShowCount: totalRegistrations - totalCheckedIn
      },
      clustering: {
        totalClusters: clusterCount,
        clusteredAttendees: await Registration.countDocuments({ 
          event: eventId, 
          cluster: { $exists: true, $ne: null, $ne: 'unassigned' } 
        })
      },
      sessions: {
        totalSessions: event.sessions?.length || 0,
        sessionDetails: sessionAnalytics,
        totalSessionEngagement: sessionData.length,
        avgSessionDuration: sessionData.reduce((sum, s) => sum + (s.duration || 0), 0) / sessionData.length || 0
      },
      insights,
      generatedAt: new Date().toISOString()
    };

    console.log(`Analytics generated successfully for ${analytics.attendance.totalRegistrations} registrations`);

    res.json(analytics);
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch analytics',
      details: error.message 
    });
  }
});

// Session tracking routes
app.post('/api/events/:eventId/sessions/:sessionId/join', authenticateToken, async (req, res) => {
  try {
    const { eventId, sessionId } = req.params;
    const userId = req.user.userId;

    // Check if user is registered for the event
    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    });

    if (!registration) {
      return res.status(403).json({ error: 'Not registered for this event' });
    }

    // Create session tracking record
    const sessionTracking = new SessionTracking({
      event: eventId,
      attendee: userId,
      session: sessionId
    });

    await sessionTracking.save();

    // Emit real-time update
    io.to(eventId).emit('session_join', {
      sessionId,
      attendeeId: userId,
      joinTime: sessionTracking.joinTime
    });

    res.json({
      message: 'Joined session successfully',
      sessionId,
      joinTime: sessionTracking.joinTime
    });
  } catch (error) {
    console.error('Session join error:', error);
    res.status(500).json({ error: 'Failed to join session' });
  }
});

app.post('/api/events/:eventId/sessions/:sessionId/leave', authenticateToken, async (req, res) => {
  try {
    const { eventId, sessionId } = req.params;
    const userId = req.user.userId;

    // Find and update session tracking record
    const sessionTracking = await SessionTracking.findOne({
      event: eventId,
      attendee: userId,
      session: sessionId,
      leaveTime: { $exists: false }
    });

    if (!sessionTracking) {
      return res.status(404).json({ error: 'Session tracking record not found' });
    }

    const leaveTime = new Date();
    const duration = Math.round((leaveTime - sessionTracking.joinTime) / 1000 / 60); // Duration in minutes

    sessionTracking.leaveTime = leaveTime;
    sessionTracking.duration = duration;
    await sessionTracking.save();

    // Emit real-time update
    io.to(eventId).emit('session_leave', {
      sessionId,
      attendeeId: userId,
      leaveTime,
      duration
    });

    res.json({
      message: 'Left session successfully',
      sessionId,
      leaveTime,
      duration
    });
  } catch (error) {
    console.error('Session leave error:', error);
    res.status(500).json({ error: 'Failed to leave session' });
  }
});

// User profile routes
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Ensure all required fields have default values
    const safeProfile = {
      _id: user._id,
      username: user.username || '',
      email: user.email || '',
      firstName: user.firstName || '',
      lastName: user.lastName || '',
      role: user.role || 'attendee',
      interests: user.interests || [],
      professionalRole: user.professionalRole || '',
      createdAt: user.createdAt || new Date()
    };

    res.json(safeProfile);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch profile',
      details: error.message 
    });
  }
});

// My events route
app.get('/api/my-events', authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'organizer') {
      // Get events created by organizer
      const events = await Event.find({ organizer: req.user.userId })
        .sort({ date: 1 });
      res.json(events);
    } else {
      // Get events registered by attendee
      const registrations = await Registration.find({ attendee: req.user.userId })
        .populate('event')
        .sort({ 'event.date': 1 });
      
      const events = registrations.map(reg => ({
        ...reg.event.toObject(),
        registrationId: reg._id,
        checkedIn: reg.checkedIn,
        cluster: reg.cluster
      }));
      
      res.json(events);
    }
  } catch (error) {
    console.error('Get my events error:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});
// Get attendee's own registration for an event (ADD THIS TO YOUR BACKEND)
app.get('/api/events/:eventId/my-registration', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const userId = req.user.userId;

    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    res.json(registration);
  } catch (error) {
    console.error('Get my registration error:', error);
    res.status(500).json({ error: 'Failed to fetch registration' });
  }
});
app.get('/api/test-uploads', (req, res) => {
    const uploadsPath = path.join(__dirname, 'uploads');
    
    try {
        const files = fs.readdirSync(uploadsPath);
        res.json({
            uploadsDirectory: uploadsPath,
            exists: fs.existsSync(uploadsPath),
            fileCount: files.length,
            files: files.slice(0, 10), // Show first 10 files
            permissions: fs.constants.F_OK
        });
    } catch (error) {
        res.status(500).json({
            error: 'Could not read uploads directory',
            details: error.message,
            uploadsPath
        });
    }
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    // Check database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
    
    // Get some basic stats
    const userCount = await User.countDocuments();
    const eventCount = await Event.countDocuments();
    const registrationCount = await Registration.countDocuments();

    res.json({
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      database: dbStatus,
      stats: {
        users: userCount,
        events: eventCount,
        registrations: registrationCount
      },
      version: '1.0.0'
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
server.listen(PORT, () => {
  console.log(`EventHive backend server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('Server closed');
      process.exit(0);
    });
  });
});

module.exports = {
  generateQRCode,
  calculateClusteringMetrics
};
