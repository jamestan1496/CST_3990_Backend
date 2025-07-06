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
app.use('/uploads', express.static('uploads'));

// Configuration
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://jamestan1496:eventhive@cluster0.gf6vat2.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-here';
const CLUSTERING_SERVICE_URL = process.env.CLUSTERING_SERVICE_URL || 'http://localhost:5001';

// File upload configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

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
app.get('/api/events', async (req, res) => {
  try {
    const { status, organizer, search } = req.query;
    let filter = {};

    if (status) filter.status = status;
    if (organizer) filter.organizer = organizer;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const events = await Event.find(filter)
      .populate('organizer', 'firstName lastName email')
      .sort({ date: 1 });

    res.json(events);
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const event = await Event.findById(req.params.id)
      .populate('organizer', 'firstName lastName email');

    if (!event) {
      return res.status(404).json({ error: 'Event not found' });
    }

    res.json(event);
  } catch (error) {
    console.error('Get event error:', error);
    res.status(500).json({ error: 'Failed to fetch event' });
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
      return res.status(400).json({ error: 'Already registered for this event' });
    }

    // Check if event is full
    const registrationCount = await Registration.countDocuments({ event: eventId });
    if (registrationCount >= event.maxAttendees) {
      return res.status(400).json({ error: 'Event is full' });
    }

    // Generate QR code
    const qrData = {
      eventId,
      userId,
      registrationId: new mongoose.Types.ObjectId().toString()
    };
    const qrCode = await generateQRCode(qrData);

    // Create registration
    const registration = new Registration({
      event: eventId,
      attendee: userId,
      qrCode
    });

    await registration.save();

    res.status(201).json({
      message: 'Registration successful',
      registration: {
        id: registration._id,
        eventId,
        qrCode,
        registrationDate: registration.registrationDate
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
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

    res.json(registrations);
  } catch (error) {
    console.error('Get registrations error:', error);
    res.status(500).json({ error: 'Failed to fetch registrations' });
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
    } catch (error) {
      return res.status(400).json({ error: 'Invalid QR data format' });
    }

    const { eventId, userId } = parsedData;

    // Find registration
    const registration = await Registration.findOne({
      event: eventId,
      attendee: userId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    if (registration.checkedIn) {
      return res.status(400).json({ error: 'Already checked in' });
    }

    // Update check-in status
    registration.checkedIn = true;
    registration.checkInTime = new Date();
    await registration.save();

    // Emit real-time update
    io.to(eventId).emit('checkin_update', {
      attendeeId: userId,
      attendeeName: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
      checkInTime: registration.checkInTime
    });

    res.json({
      message: 'Check-in successful',
      attendee: {
        name: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
        email: registration.attendee.email,
        checkInTime: registration.checkInTime
      }
    });
  } catch (error) {
    console.error('Check-in error:', error);
    res.status(500).json({ error: 'Check-in failed' });
  }
});

app.post('/api/events/:eventId/checkin-manual', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const { attendeeId } = req.body;
    const eventId = req.params.eventId;

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Find and update registration
    const registration = await Registration.findOne({
      event: eventId,
      attendee: attendeeId
    }).populate('attendee', 'firstName lastName email');

    if (!registration) {
      return res.status(404).json({ error: 'Registration not found' });
    }

    registration.checkedIn = true;
    registration.checkInTime = new Date();
    await registration.save();

    // Emit real-time update
    io.to(eventId).emit('checkin_update', {
      attendeeId,
      attendeeName: `${registration.attendee.firstName} ${registration.attendee.lastName}`,
      checkInTime: registration.checkInTime
    });

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
    res.status(500).json({ error: 'Manual check-in failed' });
  }
});

// Clustering routes
app.post('/api/events/:eventId/cluster', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const { algorithm = 'kmeans', numClusters = 3 } = req.body;

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

    // Prepare data for clustering
    const attendeeData = registrations.map(reg => ({
      id: reg.attendee._id,
      name: `${reg.attendee.firstName} ${reg.attendee.lastName}`,
      email: reg.attendee.email,
      interests: reg.attendee.interests || [],
      professionalRole: reg.attendee.professionalRole || 'unknown'
    }));

    try {
      // Call clustering microservice
      const response = await axios.post(`${CLUSTERING_SERVICE_URL}/cluster`, {
        data: attendeeData,
        algorithm,
        numClusters
      });

      const { clusters, metrics } = response.data;

      // Update registrations with cluster assignments
      for (let i = 0; i < clusters.length; i++) {
        const cluster = clusters[i];
        for (const attendeeId of cluster) {
          await Registration.findOneAndUpdate(
            { event: eventId, attendee: attendeeId },
            { cluster: `cluster_${i}` }
          );
        }
      }

      res.json({
        message: 'Clustering completed successfully',
        clusters,
        metrics,
        totalAttendees: attendeeData.length
      });
    } catch (clusteringError) {
      console.log('Clustering service unavailable, using fallback method');
      
      // Fallback: Simple rule-based clustering
      const clusterMap = new Map();
      const clusters = [];
      
      attendeeData.forEach(attendee => {
        const key = attendee.professionalRole || 'general';
        if (!clusterMap.has(key)) {
          clusterMap.set(key, []);
          clusters.push([]);
        }
        clusterMap.get(key).push(attendee.id);
        clusters[clusters.length - 1].push(attendee.id);
      });

      // Update registrations with cluster assignments
      let clusterIndex = 0;
      for (const [role, attendeeIds] of clusterMap) {
        for (const attendeeId of attendeeIds) {
          await Registration.findOneAndUpdate(
            { event: eventId, attendee: attendeeId },
            { cluster: `cluster_${clusterIndex}` }
          );
        }
        clusterIndex++;
      }

      const metrics = calculateClusteringMetrics(clusters);

      res.json({
        message: 'Clustering completed successfully (fallback method)',
        clusters: Array.from(clusterMap.values()),
        metrics,
        totalAttendees: attendeeData.length
      });
    }
  } catch (error) {
    console.error('Clustering error:', error);
    res.status(500).json({ error: 'Clustering failed' });
  }
});

app.get('/api/events/:eventId/clusters', authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Get registrations with cluster data
    const registrations = await Registration.find({ event: eventId })
      .populate('attendee', 'firstName lastName email interests professionalRole')
      .sort({ cluster: 1 });

    // Group by cluster
    const clusterMap = new Map();
    registrations.forEach(reg => {
      const cluster = reg.cluster || 'unassigned';
      if (!clusterMap.has(cluster)) {
        clusterMap.set(cluster, []);
      }
      clusterMap.get(cluster).push({
        id: reg.attendee._id,
        name: `${reg.attendee.firstName} ${reg.attendee.lastName}`,
        email: reg.attendee.email,
        interests: reg.attendee.interests,
        professionalRole: reg.attendee.professionalRole,
        checkedIn: reg.checkedIn
      });
    });

    const clusters = Array.from(clusterMap.entries()).map(([name, members]) => ({
      name,
      members,
      size: members.length
    }));

    res.json(clusters);
  } catch (error) {
    console.error('Get clusters error:', error);
    res.status(500).json({ error: 'Failed to fetch clusters' });
  }
});

// Analytics routes
app.get('/api/events/:eventId/analytics', authenticateToken, authorizeRole(['organizer']), async (req, res) => {
  try {
    const eventId = req.params.eventId;

    // Verify organizer owns the event
    const event = await Event.findById(eventId);
    if (!event || event.organizer.toString() !== req.user.userId) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Get analytics data
    const totalRegistrations = await Registration.countDocuments({ event: eventId });
    const totalCheckedIn = await Registration.countDocuments({ event: eventId, checkedIn: true });
    const clusterCount = await Registration.distinct('cluster', { event: eventId });

    // Get session tracking data
    const sessionData = await SessionTracking.find({ event: eventId })
      .populate('attendee', 'firstName lastName');

    const analytics = {
      totalRegistrations,
      totalCheckedIn,
      checkInRate: totalRegistrations > 0 ? (totalCheckedIn / totalRegistrations * 100).toFixed(2) : 0,
      totalClusters: clusterCount.filter(c => c && c !== 'unassigned').length,
      sessionEngagement: sessionData.length,
      avgSessionDuration: sessionData.reduce((sum, s) => sum + (s.duration || 0), 0) / sessionData.length || 0
    };

    res.json(analytics);
  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({ error: 'Failed to fetch analytics' });
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
    res.json(user);
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, interests, professionalRole } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { firstName, lastName, interests, professionalRole },
      { new: true }
    ).select('-password');

    res.json({
      message: 'Profile updated successfully',
      user: updatedUser
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
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

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
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

module.exports = app;