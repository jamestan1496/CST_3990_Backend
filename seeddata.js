const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
require('dotenv').config();

// Import your schemas (assuming they're in the same file structure)
// If using single file, copy the schemas from server.js

// User Schema
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

// Event Schema
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

// Registration Schema
const registrationSchema = new mongoose.Schema({
  event: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
  attendee: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  qrCode: String,
  checkedIn: { type: Boolean, default: false },
  checkInTime: Date,
  cluster: String,
  registrationDate: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Event = mongoose.model('Event', eventSchema);
const Registration = mongoose.model('Registration', registrationSchema);

// Demo Data
const demoUsers = [
  // Organizers
  {
    username: 'sarah_chen',
    email: 'sarah.chen@eventhive.com',
    password: 'demo123',
    role: 'organizer',
    firstName: 'Sarah',
    lastName: 'Chen',
    interests: ['event-planning', 'technology', 'networking'],
    professionalRole: 'Event Manager'
  },
  {
    username: 'mike_johnson',
    email: 'mike.johnson@eventhive.com',
    password: 'demo123',
    role: 'organizer',
    firstName: 'Mike',
    lastName: 'Johnson',
    interests: ['conferences', 'business', 'innovation'],
    professionalRole: 'Conference Director'
  },
  
  // Attendees
  {
    username: 'alex_smith',
    email: 'alex.smith@techcorp.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Alex',
    lastName: 'Smith',
    interests: ['artificial-intelligence', 'machine-learning', 'python'],
    professionalRole: 'Software Engineer'
  },
  {
    username: 'emma_davis',
    email: 'emma.davis@designstudio.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Emma',
    lastName: 'Davis',
    interests: ['ui-design', 'user-experience', 'creativity'],
    professionalRole: 'UX Designer'
  },
  {
    username: 'james_wilson',
    email: 'james.wilson@startup.io',
    password: 'demo123',
    role: 'attendee',
    firstName: 'James',
    lastName: 'Wilson',
    interests: ['entrepreneurship', 'business-strategy', 'funding'],
    professionalRole: 'Startup Founder'
  },
  {
    username: 'lisa_garcia',
    email: 'lisa.garcia@marketing.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Lisa',
    lastName: 'Garcia',
    interests: ['digital-marketing', 'social-media', 'analytics'],
    professionalRole: 'Marketing Manager'
  },
  {
    username: 'david_lee',
    email: 'david.lee@datatech.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'David',
    lastName: 'Lee',
    interests: ['data-science', 'analytics', 'machine-learning'],
    professionalRole: 'Data Scientist'
  },
  {
    username: 'sophia_martinez',
    email: 'sophia.martinez@cloudtech.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Sophia',
    lastName: 'Martinez',
    interests: ['cloud-computing', 'devops', 'automation'],
    professionalRole: 'DevOps Engineer'
  },
  {
    username: 'ryan_taylor',
    email: 'ryan.taylor@fintech.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Ryan',
    lastName: 'Taylor',
    interests: ['fintech', 'blockchain', 'cryptocurrency'],
    professionalRole: 'Financial Analyst'
  },
  {
    username: 'maria_rodriguez',
    email: 'maria.rodriguez@healthtech.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Maria',
    lastName: 'Rodriguez',
    interests: ['healthcare', 'medical-technology', 'innovation'],
    professionalRole: 'Product Manager'
  },
  {
    username: 'kevin_brown',
    email: 'kevin.brown@cybersec.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Kevin',
    lastName: 'Brown',
    interests: ['cybersecurity', 'privacy', 'security'],
    professionalRole: 'Security Analyst'
  },
  {
    username: 'anna_kim',
    email: 'anna.kim@ailab.com',
    password: 'demo123',
    role: 'attendee',
    firstName: 'Anna',
    lastName: 'Kim',
    interests: ['artificial-intelligence', 'research', 'innovation'],
    professionalRole: 'AI Researcher'
  }
];

const generateQRCode = async (data) => {
  try {
    const qrCodeData = await QRCode.toDataURL(JSON.stringify(data));
    return qrCodeData;
  } catch (error) {
    console.error('QR generation error:', error);
    return null;
  }
};

const seedDatabase = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/eventhive', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    console.log('Connected to MongoDB');
    
    // Clear existing data
    await User.deleteMany({});
    await Event.deleteMany({});
    await Registration.deleteMany({});
    console.log('Cleared existing data');
    
    // Create users
    const users = [];
    for (const userData of demoUsers) {
      const hashedPassword = await bcrypt.hash(userData.password, 10);
      const user = new User({
        ...userData,
        password: hashedPassword
      });
      users.push(user);
    }
    
    const createdUsers = await User.insertMany(users);
    console.log(`Created ${createdUsers.length} users`);
    
    // Find organizers and attendees
    const organizers = createdUsers.filter(user => user.role === 'organizer');
    const attendees = createdUsers.filter(user => user.role === 'attendee');
    
    // Create events
    const currentDate = new Date();
    const demoEvents = [
      {
        title: 'AI & Machine Learning Summit 2025',
        description: 'Join industry leaders to explore the latest breakthroughs in artificial intelligence and machine learning. Learn about practical applications, ethical considerations, and future trends shaping the technology landscape.',
        date: new Date(currentDate.getTime() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        time: '09:00',
        location: 'Dubai World Trade Centre, Dubai',
        organizer: organizers[0]._id,
        maxAttendees: 150,
        status: 'upcoming',
        sessions: [
          {
            title: 'Opening Keynote: The Future of AI',
            speaker: 'Dr. Sarah Chen',
            speakerBio: 'Leading AI researcher with 15+ years of experience in machine learning and neural networks.',
            startTime: '09:00',
            endTime: '10:00',
            description: 'An overview of emerging AI trends and their impact on various industries.'
          },
          {
            title: 'Deep Learning in Practice',
            speaker: 'Prof. Michael Thompson',
            speakerBio: 'Computer Science professor specializing in deep learning and computer vision.',
            startTime: '10:30',
            endTime: '11:30',
            description: 'Hands-on workshop covering practical implementation of deep learning models.'
          },
          {
            title: 'Ethics in AI Development',
            speaker: 'Dr. Emily Watson',
            speakerBio: 'Ethics consultant and researcher in AI bias and fairness.',
            startTime: '14:00',
            endTime: '15:00',
            description: 'Discussion on ethical considerations and responsible AI development practices.'
          }
        ]
      },
      {
        title: 'Tech Startup Pitch Night',
        description: 'An exciting evening where innovative startups present their game-changing ideas to investors, mentors, and the tech community. Network with entrepreneurs and discover the next big thing in technology.',
        date: new Date(currentDate.getTime() + 3 * 24 * 60 * 60 * 1000), // 3 days from now
        time: '18:00',
        location: 'Innovation Hub, DIFC, Dubai',
        organizer: organizers[1]._id,
        maxAttendees: 80,
        status: 'upcoming',
        sessions: [
          {
            title: 'Startup Pitch Session 1',
            speaker: 'Various Entrepreneurs',
            speakerBio: 'Promising startup founders presenting their innovative solutions.',
            startTime: '18:30',
            endTime: '19:30',
            description: 'First round of startup pitches featuring fintech and healthtech startups.'
          },
          {
            title: 'Networking & Refreshments',
            speaker: 'All Attendees',
            speakerBio: 'Interactive networking session with light refreshments.',
            startTime: '19:30',
            endTime: '20:00',
            description: 'Opportunity to connect with fellow entrepreneurs and investors.'
          },
          {
            title: 'Startup Pitch Session 2',
            speaker: 'Various Entrepreneurs',
            speakerBio: 'Second batch of innovative startup founders.',
            startTime: '20:00',
            endTime: '21:00',
            description: 'Second round featuring AI and blockchain startups.'
          }
        ]
      },
      {
        title: 'UX/UI Design Workshop',
        description: 'A comprehensive workshop covering modern design principles, user research methods, and prototyping tools. Perfect for designers looking to enhance their skills and learn industry best practices.',
        date: new Date(currentDate.getTime() + 14 * 24 * 60 * 60 * 1000), // 14 days from now
        time: '10:00',
        location: 'Design Studio, Dubai Design District',
        organizer: organizers[0]._id,
        maxAttendees: 40,
        status: 'upcoming',
        sessions: [
          {
            title: 'Introduction to User-Centered Design',
            speaker: 'Emma Davis',
            speakerBio: 'Senior UX Designer with expertise in user research and interface design.',
            startTime: '10:00',
            endTime: '11:30',
            description: 'Fundamentals of user-centered design methodology and best practices.'
          },
          {
            title: 'Prototyping with Figma',
            speaker: 'Alex Rodriguez',
            speakerBio: 'Product Designer and Figma expert with 8+ years of experience.',
            startTime: '12:00',
            endTime: '13:30',
            description: 'Hands-on workshop creating interactive prototypes using Figma.'
          },
          {
            title: 'Design System Implementation',
            speaker: 'Jordan Lee',
            speakerBio: 'Design Systems lead at major tech company.',
            startTime: '14:30',
            endTime: '16:00',
            description: 'Building and maintaining scalable design systems for products.'
          }
        ]
      },
      {
        title: 'Digital Marketing Mastery',
        description: 'Learn the latest digital marketing strategies, tools, and techniques from industry experts. Covering social media marketing, SEO, content marketing, and performance analytics.',
        date: new Date(currentDate.getTime() + 21 * 24 * 60 * 60 * 1000), // 21 days from now
        time: '13:00',
        location: 'Marketing Hub, Business Bay, Dubai',
        organizer: organizers[1]._id,
        maxAttendees: 100,
        status: 'upcoming',
        sessions: [
          {
            title: 'Social Media Strategy in 2025',
            speaker: 'Lisa Garcia',
            speakerBio: 'Digital marketing expert with focus on social media and content strategy.',
            startTime: '13:00',
            endTime: '14:00',
            description: 'Latest trends and strategies for effective social media marketing.'
          },
          {
            title: 'SEO & Content Marketing',
            speaker: 'Mark Johnson',
            speakerBio: 'SEO consultant and content strategist with 10+ years of experience.',
            startTime: '14:30',
            endTime: '15:30',
            description: 'Advanced SEO techniques and content marketing strategies.'
          },
          {
            title: 'Analytics & Performance Tracking',
            speaker: 'Sarah Kim',
            speakerBio: 'Data analyst specializing in marketing metrics and ROI optimization.',
            startTime: '16:00',
            endTime: '17:00',
            description: 'Using analytics tools to measure and optimize marketing performance.'
          }
        ]
      },
      {
        title: 'Blockchain & Cryptocurrency Forum',
        description: 'Explore the world of blockchain technology, cryptocurrency, and decentralized finance. Learn about investment opportunities, regulatory landscape, and technical innovations.',
        date: new Date(currentDate.getTime() - 2 * 24 * 60 * 60 * 1000), // 2 days ago (completed)
        time: '11:00',
        location: 'Crypto Centre, DMCC, Dubai',
        organizer: organizers[0]._id,
        maxAttendees: 120,
        status: 'completed',
        sessions: [
          {
            title: 'Blockchain Fundamentals',
            speaker: 'Dr. Ahmed Hassan',
            speakerBio: 'Blockchain researcher and cryptocurrency expert.',
            startTime: '11:00',
            endTime: '12:00',
            description: 'Understanding blockchain technology and its applications.'
          },
          {
            title: 'DeFi Investment Strategies',
            speaker: 'Ryan Taylor',
            speakerBio: 'Financial analyst specializing in decentralized finance.',
            startTime: '13:00',
            endTime: '14:00',
            description: 'Investment strategies and risk management in DeFi.'
          },
          {
            title: 'Regulatory Landscape',
            speaker: 'Maria Lopez',
            speakerBio: 'Legal expert in cryptocurrency and blockchain regulations.',
            startTime: '14:30',
            endTime: '15:30',
            description: 'Current regulatory environment and compliance requirements.'
          }
        ]
      },
      {
        title: 'Cybersecurity Best Practices',
        description: 'Essential cybersecurity knowledge for businesses and individuals. Learn about threat detection, data protection, and security frameworks to safeguard digital assets.',
        date: new Date(currentDate.getTime() + 10 * 24 * 60 * 60 * 1000), // 10 days from now
        time: '14:00',
        location: 'Security Center, Dubai Internet City',
        organizer: organizers[1]._id,
        maxAttendees: 60,
        status: 'upcoming',
        sessions: [
          {
            title: 'Threat Landscape 2025',
            speaker: 'Kevin Brown',
            speakerBio: 'Cybersecurity analyst with expertise in threat intelligence.',
            startTime: '14:00',
            endTime: '15:00',
            description: 'Current cybersecurity threats and attack vectors.'
          },
          {
            title: 'Data Protection Strategies',
            speaker: 'Jennifer White',
            speakerBio: 'Data protection officer and privacy consultant.',
            startTime: '15:30',
            endTime: '16:30',
            description: 'Implementing effective data protection and privacy measures.'
          },
          {
            title: 'Security Framework Implementation',
            speaker: 'Michael Chen',
            speakerBio: 'Security architect with experience in enterprise security.',
            startTime: '17:00',
            endTime: '18:00',
            description: 'Building and implementing comprehensive security frameworks.'
          }
        ]
      }
    ];
    
    const createdEvents = await Event.insertMany(demoEvents);
    console.log(`Created ${createdEvents.length} events`);
    
    // Create registrations
    const registrations = [];
    
    for (const event of createdEvents) {
      // Register 60-80% of attendees to each event
      const numRegistrations = Math.floor(attendees.length * (0.6 + Math.random() * 0.2));
      const shuffledAttendees = attendees.sort(() => 0.5 - Math.random());
      
      for (let i = 0; i < numRegistrations; i++) {
        const attendee = shuffledAttendees[i];
        const qrData = {
          eventId: event._id,
          userId: attendee._id,
          registrationId: new mongoose.Types.ObjectId().toString()
        };
        
        const qrCode = await generateQRCode(qrData);
        
        // Some attendees are already checked in (for completed events or demo purposes)
        const isCheckedIn = event.status === 'completed' || Math.random() < 0.3;
        
        registrations.push({
          event: event._id,
          attendee: attendee._id,
          qrCode,
          checkedIn: isCheckedIn,
          checkInTime: isCheckedIn ? new Date(event.date.getTime() + Math.random() * 2 * 60 * 60 * 1000) : null,
          cluster: null, // Will be assigned when clustering is performed
          registrationDate: new Date(event.date.getTime() - Math.random() * 14 * 24 * 60 * 60 * 1000)
        });
      }
    }
    
    const createdRegistrations = await Registration.insertMany(registrations);
    console.log(`Created ${createdRegistrations.length} registrations`);
    
    // Assign some clusters to registrations (simulate clustering results)
    const clusterNames = ['tech_innovators', 'business_leaders', 'creative_minds', 'data_experts'];
    for (const registration of createdRegistrations) {
      if (Math.random() < 0.7) { // 70% chance of being assigned to a cluster
        registration.cluster = clusterNames[Math.floor(Math.random() * clusterNames.length)];
        await registration.save();
      }
    }
    
    console.log('✅ Demo data seeded successfully!');
    console.log('\n📊 Demo Data Summary:');
    console.log(`👥 Users: ${createdUsers.length} (${organizers.length} organizers, ${attendees.length} attendees)`);
    console.log(`🎉 Events: ${createdEvents.length}`);
    console.log(`📝 Registrations: ${createdRegistrations.length}`);
    console.log('\n🔐 Demo Login Credentials:');
    console.log('Organizer: sarah.chen@eventhive.com / demo123');
    console.log('Organizer: mike.johnson@eventhive.com / demo123');
    console.log('Attendee: alex.smith@techcorp.com / demo123');
    console.log('Attendee: emma.davis@designstudio.com / demo123');
    console.log('\n🚀 Your EventHive demo is ready!');
    
  } catch (error) {
    console.error('Error seeding database:', error);
  } finally {
    await mongoose.connection.close();
    console.log('Database connection closed');
  }
};

// Run the seed function
seedDatabase();